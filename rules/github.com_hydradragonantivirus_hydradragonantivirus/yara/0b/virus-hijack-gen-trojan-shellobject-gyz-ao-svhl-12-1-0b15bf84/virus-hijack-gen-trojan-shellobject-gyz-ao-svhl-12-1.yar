rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aO_sVhl_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aO@sVhl_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f4702e0b8334a07e989bcfc93474c46bc8e4e0991f8e8ebc007b8776775d2b8"

  strings:
    $s1 = "@sizeInBytes >= count" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}