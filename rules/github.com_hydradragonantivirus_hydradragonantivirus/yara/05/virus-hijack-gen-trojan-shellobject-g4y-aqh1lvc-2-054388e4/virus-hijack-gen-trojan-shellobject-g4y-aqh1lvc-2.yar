rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_aqH1LVc_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@aqH1LVc_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a7a809460f39f42e4a4486297cdc59be4b84c425a2ee39449c2bea54693f872"

  strings:
    $s1 = "}must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}