rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_40 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9379f3200f35a1fc600ee706307a042d2cec4e6b7b8fbc9097cb383990ff3450"

  strings:
    $s1 = "|4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}