rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_a8TFxTj_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@a8TFxTj_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a57358d0e0c62149b6aa497ef6157d9f55da634aa69bd3baa4c43ab0be3b9ae8"

  strings:
    $s1 = "  -O, --show-options, --usage  go to command-line options node" fullword ascii
    $s2 = "  info --show-options emacs    start at node with emacs' command line options" fullword ascii
    $s3 = "From:`\"/" fullword ascii
    $s4 = "  look" fullword ascii
    $s5 = "0<FONT " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}