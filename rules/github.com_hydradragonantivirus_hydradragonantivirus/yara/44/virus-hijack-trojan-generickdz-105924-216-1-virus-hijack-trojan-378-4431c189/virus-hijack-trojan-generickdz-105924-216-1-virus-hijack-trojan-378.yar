rule _Virus_Hijack_Trojan_GenericKDZ_105924_216_1_Virus_Hijack_Trojan_378 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_216_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_233_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_235_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_2_1.vir, Virus.Hooker_Trojan.GenericKD.72483755_2_1.vir, Virus.Hooker_Trojan.VB.Agent.AWT_1.vir, Virus.Hooker_Win32.Ramnit.N_1.vir, Virus.Infector _Win32.Expiro.Gen.7_1.vir, Virus.Infector_Gen.Heur.Mint.Hiamoe.20_2.vir, Virus.Infector_Gen.Trojan.Heur.ei0frDAUi!mib_1.vir, Virus.Infector_Gen.Trojan.Malware.1q3@aunLb5ni_1.vir, Virus.Infector_Gen.Trojan.Malware.Mq3@aunLb5ni_3.vir, VirusShareTrojanClick331128_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ad7bcd15f8be25b698773c3aa63c2502686279ec65ed106cb9718595461dc4a"
    hash2       = "30f2f4066055982aa217e1da873c8c5306b812730a14c821c3dca50fec8f4fef"
    hash3       = "aa2256999cc65afcba5d973b00acb1764275d2b797488387d5af52b972889f81"
    hash4       = "6dcb20428ef096b85384de6f0fdea3d77a5552c3c7b8edde8875357bef236f89"
    hash5       = "b4c4605b32dbcbf1bda88bc05b2a71757e06e572ffb1dab58c4c0d28f9715582"
    hash6       = "6d614471691193440e0326fd127d26c31ddc5b830f82a8df693c3178ec5692a6"
    hash7       = "4b0e91f435ebc6fcf8b35f71c7081e88093bff24ab27c2c4b4dcb920bd6a5a07"
    hash8       = "502710441c7835b16731383c15ea3e9d41f750126c9f31da55c258ed51137657"
    hash9       = "966f43636e45e27868a30ae7d5e122e22ee997a61caacb56ac898ac7dfa66462"
    hash10      = "c52fa281ae4471782914d02f1c476f9ba269ecae9390e4a883e97c501f86cbbd"
    hash11      = "85fc817c1c8dda19e804a3aaa4081ca4f0824b066ad3e0bbc5a67e4645b7fe98"
    hash12      = "b7031bd32f110b3183848fc7a05313bbfd2581936c862e20d7c5b63fb8e60cde"
    hash13      = "a1b31b78023158adf0360947d5d12512ac0132b3b758720480e06341fe058946"

  strings:
    $s1  = "uses implicit create command line from a process server" fullword ascii
    $s2  = "specifies a script file to be processed at the beginning of a session (including after .restart)" fullword ascii
    $s3  = "disables handle inheritance for created processes" fullword ascii
    $s4  = "install as AeDebug debugger with given command tail" fullword ascii
    $s5  = "-iaec <Command>" fullword ascii
    $s6  = "    id: com port name, of the form com2 or \\\\.\\com12" fullword ascii
    $s7  = "appends to an Unicode log file" fullword ascii
    $s8  = "opens a new Unicode log file" fullword ascii
    $s9  = "tells the debugger to connect to the local machine" fullword ascii
    $s10 = "install as AeDebug debugger" fullword ascii
    $s11 = "install dbgeng URL protocols" fullword ascii
    $s12 = "turns on kd quiet mode (equivalent to KDQUIET)" fullword ascii
    $s13 = "-cfr <file>" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}