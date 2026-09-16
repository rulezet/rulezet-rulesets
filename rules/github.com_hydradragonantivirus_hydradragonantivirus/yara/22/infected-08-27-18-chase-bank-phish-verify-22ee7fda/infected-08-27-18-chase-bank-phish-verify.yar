rule infected_08_27_18_chase_bank_phish_verify {
  meta:
    description = "chase - file verify.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "8c9a2a71e438b74d92a0454c69097e952c23c5d5fc78899f965256852d6c71ef"

  strings:
    $s1 = "$recipient =" fullword ascii
    $s2 = "$message .= \"Password              : \".$_POST['Password'].\"\\n\";" fullword ascii
    $s4 = "header(\"Location:  log.htm\");" fullword ascii
    $s5 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s6 = "$message .= \"---- : || tHAnks tO PHish || :------\\n\";" fullword ascii
    $s7 = "$message .= \"User ID             : \".$_POST['UserID'].\"\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}