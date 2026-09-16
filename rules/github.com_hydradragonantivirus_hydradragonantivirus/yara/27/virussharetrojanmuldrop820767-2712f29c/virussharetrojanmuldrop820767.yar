rule VirusShareTrojanMulDrop820767 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanMulDrop820767.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d56baf0409be57c23a48010e3f53567c2b53d53fb8ca00c1cae91fff519a085"

  strings:
    $s1 = "SrB78hv0mcGFLvVfsY.RFKoPhHG5UW6URkoJf+t8ouT9eXnQXf3oaFME+hdTrd9DMsDl5OW4Luh`1[[System.Object, mscorlib, Version=2.0.0.0, Culture" ascii
    $s2 = "Skype Hack Inc.," fullword wide
    $s3 = "Skype Hack" fullword wide
    $s4 = "<Module>{97484FF1-A97E-4CF6-A1CF-3F106F891528}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}