rule Virus_Hijack_Win32_Doboc_Gen_1_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Doboc.Gen.1_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "560168600cfe7b47593584bb77ebe32a4b5e917e39dedc4ae014d536bbc47ef7"

  strings:
    $s1 = "cusHy$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}