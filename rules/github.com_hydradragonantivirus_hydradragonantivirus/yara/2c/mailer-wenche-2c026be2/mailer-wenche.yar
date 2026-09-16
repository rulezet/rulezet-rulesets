rule mailer_wenche {
  meta:
    description = "work1 - file mailer_wenche.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "d70e877c611771ca1939f1863bb268abc96b364ee1024f0e9176e80ce4d5bfc9"

  strings:
    $s1 = "$jwgpxlzblkepa = base64_decode($_POST['tdluhqtnmzr']);  " fullword ascii
    $s2 = "$jewrqwbnlk = base64_decode($_POST['ylxqjqbcn']); " fullword ascii
    $s3 = "$fcublsqtpae = base64_decode($_POST['qqifquaqdzvp']);  " fullword ascii
    $s4 = "$xaouf = base64_decode($_POST['nrsf']); " fullword ascii
    $s5 = "$jfnbrsjfq = mail($jewrqwbnlk, $xaouf, $jwgpxlzblkepa, $fcublsqtpae);" fullword ascii
    $s6 = "if($jfnbrsjfq){echo 'vwkxlpc';} else {echo 'yfbhn : ' . $jfnbrsjfq;} " fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}