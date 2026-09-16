rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0832e53398258d75986f3af2354a569881a28b5c1c8729b0f63d0a39f218bf03"

  strings:
    $s1  = "[+] Taget process : %s " fullword ascii
    $s2  = "[!] Delay Execution Failed ! " fullword ascii
    $s3  = "[+] process handler is set with pid: %d" fullword ascii
    $s4  = "[+] Running Delay Execution for %d ... " fullword ascii
    $s5  = "[!] process handle failed" fullword ascii
    $s6  = "[+] Running WriteProcessMemory ...." fullword ascii
    $s7  = "[-] Failed in making the thread time critical " fullword ascii
    $s8  = "[+] DONE ! " fullword ascii
    $s9  = "[+] Debugging is DONE " fullword ascii
    $s10 = "[!] Thread is with low Priority" fullword ascii
    $s11 = "[+] Thread is time critical " fullword ascii
    $s12 = "[+] Running NtProtectVirtualMemory ...." fullword ascii
    $s13 = "[+] Running VirtualAllocEx ...." fullword ascii
    $s14 = " [ + ] DONE " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}