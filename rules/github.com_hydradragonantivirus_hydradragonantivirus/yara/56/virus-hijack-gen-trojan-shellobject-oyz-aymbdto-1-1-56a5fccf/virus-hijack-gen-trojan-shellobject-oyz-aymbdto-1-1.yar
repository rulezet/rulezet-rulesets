rule Virus_Hijack_Gen_Trojan_ShellObject_oyZ_ayMBdto_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oyZ@ayMBdto_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76b8eeed1ed52dcd17221bec14f011a2fad6ffa1ba43bd8b1aec402a04cbb346"

  strings:
    $s1 = "SELECT Name, VideoProcessor FROM Win32_VideoController" fullword wide
    $s2 = "Shell Infrastructure Host" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}