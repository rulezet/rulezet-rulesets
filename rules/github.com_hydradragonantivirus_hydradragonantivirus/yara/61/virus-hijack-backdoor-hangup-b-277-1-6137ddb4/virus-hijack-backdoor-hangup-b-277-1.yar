rule Virus_Hijack_Backdoor_Hangup_B_277_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_277_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "854eb94b9a305f29aab6176facf0b80800c6e9c0e71326f8c3da2988cece8b65"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
    $s2 = "7,0,1123,42427 @Commit: ecb34f85ec92e1b3c814edf7da83337e199e7f66" fullword wide
    $s3 = "7.0.11 @Commit: ecb34f85ec92e1b3c814edf7da83337e199e7f66" fullword wide
    $s4 = "ation></ms_compatibility:compatibility></assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}