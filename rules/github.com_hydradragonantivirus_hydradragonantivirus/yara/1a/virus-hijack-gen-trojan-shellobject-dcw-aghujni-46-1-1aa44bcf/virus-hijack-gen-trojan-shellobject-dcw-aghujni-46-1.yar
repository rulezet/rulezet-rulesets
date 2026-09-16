rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_46_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7614962741fae371ced47c468191ed0fb1831afa39f6b2d5b01f7e6444928bc7"

  strings:
    $s1 = "Apparently should be %d,%d,decompressor will try reading with sampling %d,%d" fullword ascii
    $s2 = "D3DX9 Shader Compiler" fullword ascii
    $s3 = "LZWDecode: Corrupted LZW table" fullword ascii
    $s4 = "LZW compression is not available to due to Unisys patent enforcement" fullword ascii
    $s5 = "0123456789ABCDEF deflate 1.1.3 Copyright 1995-1998 Jean-loup Gailly " fullword ascii
    $s6 = "LZWDecode: Unexpected end of code table" fullword ascii
    $s7 = "Software\\Microsoft\\Internet Explorer\\Main\\Start Page" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}