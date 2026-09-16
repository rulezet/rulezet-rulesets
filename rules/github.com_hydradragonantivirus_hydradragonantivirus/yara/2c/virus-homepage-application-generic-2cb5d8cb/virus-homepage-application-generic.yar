rule Virus_Homepage__Application_Generic {
  meta:
    description = "datamaliciousorder - file Virus.Homepage _Application.Generic.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac68e97a772195182645c5148f1c251d655c0bfbef57c3565ffb5fb44cba45c"

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