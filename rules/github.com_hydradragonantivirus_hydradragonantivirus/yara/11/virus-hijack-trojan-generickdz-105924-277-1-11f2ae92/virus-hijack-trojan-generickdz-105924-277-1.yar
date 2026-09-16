rule Virus_Hijack_Trojan_GenericKDZ_105924_277_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_277_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09b933327644eda2a3410b8b9d35fced96fbcf8d36e82c6224bef524ae794580"

  strings:
    $s1 = "OLE error %.8x.Method '%s' not supported by automation object/Variant does not reference an automation object7Dispatch methods d" wide
    $s2 = "this->get_Count((long*)&Count)" fullword ascii
    $s3 = "System jB" fullword ascii
    $s4 = "Browser Helper Objects\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}