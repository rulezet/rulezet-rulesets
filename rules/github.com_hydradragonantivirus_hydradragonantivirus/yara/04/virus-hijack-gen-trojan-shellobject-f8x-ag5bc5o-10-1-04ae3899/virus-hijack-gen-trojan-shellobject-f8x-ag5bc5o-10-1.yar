rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b63c8b8957eb0d68747833917a524379ceb72d10cf98716e30d68116a3e3d9fa"

  strings:
    $s1 = "Fneed dictionary" fullword ascii
    $s2 = "Encode;'" fullword ascii
    $s3 = "Simp#lepOb" fullword ascii
    $s4 = "Hogger" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}