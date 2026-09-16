rule backdoor__1715ce0b {
  meta:
    description = "work1 - file backdoor_.1715ce0b.ico"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "14d58a0e5c09b4a0791f8ea400d62ca17456ebd55b5e999420ea6297bd670dc9"

  strings:
    $s1 = "$_whsb8 = basename/*vox*/(/*e0iq*/trim/*kh7m*/(/*7r*/preg_replace/*iac9*/(/*8b*/rawurldecode/*zad7*/(/*t7n2x*/\"%2F%5C%28.%2A%24" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 300KB and
      (all of them)
    ) or (all of them)
}