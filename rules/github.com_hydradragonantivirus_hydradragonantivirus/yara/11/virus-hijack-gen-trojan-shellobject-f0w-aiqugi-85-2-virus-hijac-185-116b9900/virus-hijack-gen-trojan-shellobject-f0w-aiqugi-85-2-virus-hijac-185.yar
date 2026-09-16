rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_85_2_Virus_Hijac_185 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_85_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1b1a9fb160b36ba22f829ffbd02988ba821a5649910c7f2cc9b2264e0dc12f9"
    hash2       = "9dd481aae9a5d9bb4492b165f159bb9b6e7d7a9fc94fa24820790c8c1d87ee10"

  strings:
    $x1  = "- Write a Full and Kernel dump for a process named 'hang.exe' when one of its" fullword wide
    $x2  = "- Write a Mini dump for a process named 'hang.exe' when one of its" fullword wide
    $x3  = "   -k      Kill the process after cloning (-r), or at end of dump collection." fullword wide
    $s4  = "- Write a Full dump of a process with PID '4572':" fullword wide
    $s5  = "- Write a Mini first, and then a Full dump of a process with PID '4572':" fullword wide
    $s6  = "- Write 3 Mini dumps 5 seconds apart of a process named 'notepad':" fullword wide
    $s7  = "- Write up to 3 Mini dumps of a process named 'consume' when it exceeds" fullword wide
    $s8  = "- Write a Mini dump of a process named 'outlook' when total system CPU " fullword wide
    $s9  = "- Write a Full dump of a process named 'outlook' when Outlook's handle count " fullword wide
    $s10 = "   Default dump filename: PROCESSNAME_YYMMDD_HHMMSS.dmp" fullword wide
    $s11 = "- Write a Mini dump of a process named 'notepad' (only one match can exist):" fullword wide
    $s12 = "- Write up to 10 Full dumps of each 1st or 2nd chance exception of w3wp.exe:" fullword wide
    $s13 = "           Note: CLR processes are dumped as Full (-ma) due to debugging limitations." fullword wide
    $s14 = "   -wer    Queue the (largest) dump to Windows Error Reporting." fullword wide
    $s15 = "   -mk     Also write a 'Kernel' dump file." fullword wide
    $s16 = "           OS doesn't support a kernel dump (-mk) when using a clone (-r)." fullword wide
    $s17 = "   -cancel <Target Process PID>" fullword wide
    $s18 = "CreateDebuggingInterfaceFromVersionCoreCLR - Error %x (CORDBG_E_DEBUG_COMPONENT_MISSING)" fullword wide
    $s19 = "CreateDebuggingInterfaceFromVersionCoreCLR - Error %x (CORDBG_E_INCOMPATIBLE_PROTOCOL)" fullword wide
    $s20 = "The specified DLL does not have an export function named MiniDumpCallbackRoutine." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}