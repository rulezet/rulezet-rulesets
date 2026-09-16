rule Virus_Hijack_Win32_Doboc_Gen_1_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Doboc.Gen.1_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7187feef22de5dae69edab1eb666ecf4823d4ecc92b19a37f8a85275ff128e82"

  strings:
    $s1  = "Command Processor" fullword ascii
    $s2  = "Shutdown -s -t 0" fullword ascii
    $s3  = "Program Files\\Common Files\\Services\\" fullword ascii
    $s4  = "shutdown -l" fullword ascii
    $s5  = "%d.%d build %d %s" fullword ascii
    $s6  = "Address`" fullword ascii
    $s7  = "Program Files\\Internet Explorer" fullword ascii
    $s8  = "\" goto Loop" fullword ascii
    $s9  = "MS-DOS Carry out and Fail!" fullword ascii
    $s10 = "\",0, True" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}