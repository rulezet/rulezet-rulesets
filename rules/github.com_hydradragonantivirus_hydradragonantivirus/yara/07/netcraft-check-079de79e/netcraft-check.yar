rule netcraft_check {
  meta:
    description = "phishing - file netcraft_check.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "f1b491fc82cec2171389a3f9c4645416ab13d2e09cf68a3b9f1a9826a95ea3a3"

  strings:
    $s1 = "if ($v_agent == \"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 2.0.50727)\") {" fullword ascii
    $s2 = "header(\"Location: https://chase.com/\");" fullword ascii
    $s3 = "Created by legzy -- icq: 692561824 " fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}