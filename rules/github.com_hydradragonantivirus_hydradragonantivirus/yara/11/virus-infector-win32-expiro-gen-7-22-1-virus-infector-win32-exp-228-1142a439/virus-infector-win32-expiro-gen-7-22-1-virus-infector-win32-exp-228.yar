import "pe"
rule _Virus_Infector_Win32_Expiro_Gen_7_22_1_Virus_Infector_Win32_Exp_228 {
  meta:
    description = "datamaliciousorder - from files Virus.Infector_Win32.Expiro.Gen.7_22_1.vir, Virus.Infector_Win32.Expiro.Gen.7_27_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae7f6c153bc53df8fbd6ae5465aebbe2c97bd520f0542e39988ca398f4b2050c"
    hash2       = "d33d87603ef8e2e7c3624488f59c941e1c64f2cfd1b5e9c77ce48afcca5a0371"

  strings:
    $s1 = "Internal Loader Error!" fullword ascii
    $s2 = "CRC error! File content has been modified. If you run a system" fullword ascii
    $s3 = "Error while loading a DLL!" fullword ascii
    $s4 = "Decompression error!" fullword ascii
    $s5 = "Reason might be a possible virus infection!" fullword ascii
    $s6 = "Error while locating a DLL function!" fullword ascii
    $s7 = "This Program does not run on machines with active system debugger!" fullword ascii
    $s8 = "debugger, clear all breakpoints before running this program!" fullword ascii
    $s9 = "Integrity check failed! This File has been modified." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "2b3fe42b59a6c54c1699187a146367d7" and (all of them)
    ) or (all of them)
}