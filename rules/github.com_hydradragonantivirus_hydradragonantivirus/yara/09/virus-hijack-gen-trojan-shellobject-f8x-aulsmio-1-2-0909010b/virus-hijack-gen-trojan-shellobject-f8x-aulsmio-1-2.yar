rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f00633513a3a9f0ecc7cd07174b1ddfeeae8f3df427e13dea06e0c798959504"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"GrooveAuditService\" type=" ascii
    $s2  = "\" version=\"4.0.0.0\" processorArchitecture=\"X86\"></assemblyIdentity><description>Microsoft Office Groove Audit Service</desc" ascii
    $s3  = "Process: Msg = \"%s\"; Size = %d" fullword wide
    $s4  = "on><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"8.0.50608.0\" processor" ascii
    $s5  = "Connect: ERROR_PIPE_LISTENING" fullword wide
    $s6  = "ExtendedRead: ReadFile got last part of message, Total Size = %d, Last Part = %d" fullword wide
    $s7  = "Create log file failed" fullword wide
    $s8  = "Connect: PIPE_CONNECTED" fullword wide
    $s9  = "Read: OverlappedResult says ReadFile completed" fullword wide
    $s10 = "Read: OverlappedResult says ReadFile didn't complete" fullword wide
    $s11 = "Read: OverlappedResult says ReadFile hit unexpected error" fullword wide
    $s12 = "Read: ReadFile returned an unexpected error" fullword wide
    $s13 = "ExtendedRead: ReadFile hit unexpected error" fullword wide
    $s14 = "Create or open key file failed" fullword wide
    $s15 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"GrooveAuditService\" type=" ascii
    $s16 = "?Throw@GCError@@QBEXXZ" fullword ascii
    $s17 = ":asm.v3\"><ms_asmv3:security><ms_asmv3:requestedPrivileges>" fullword ascii
    $s18 = "?Open@GCRegistryKey@@QAEJK@Z" fullword ascii
    $s19 = "Microsoft Office Groove Audit Service" fullword wide
    $s20 = "Connect: ERROR_IO_PENDING" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}