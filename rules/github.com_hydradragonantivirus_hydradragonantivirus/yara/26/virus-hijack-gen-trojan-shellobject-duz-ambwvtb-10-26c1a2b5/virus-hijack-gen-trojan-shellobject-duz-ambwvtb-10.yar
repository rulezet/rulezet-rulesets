rule Virus_Hijack_Gen_Trojan_ShellObject_DuZ_amBwvTb_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DuZ@amBwvTb_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d85c0ca0f19e425db38ff3f9c8e07164a0768cad2f8f91fdc35c49d0ea663c9"

  strings:
    $s1 = "MyImgur Programming Team." fullword wide
    $s2 = ". All rights reserved." fullword ascii
    $s3 = "2An application to upload images directly to Imgur." fullword ascii
    $s4 = "An application to upload images directly to Imgur." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}