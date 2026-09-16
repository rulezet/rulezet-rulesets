rule Trojan_Autorun_Trojan_GenericKD_72517131_56_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_56_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9aa1e19c9315cf54017dff90224993b15b80991fb4fb54deac903ccb37abbc48"

  strings:
    $s1 = "[your order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}