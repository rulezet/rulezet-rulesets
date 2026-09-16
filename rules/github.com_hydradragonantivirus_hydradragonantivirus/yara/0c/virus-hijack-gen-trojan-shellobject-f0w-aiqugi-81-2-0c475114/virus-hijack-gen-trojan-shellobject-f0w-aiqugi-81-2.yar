rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_81_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_81_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a47958818ff2857d87238e6eae4914230b7d9b5273fe004c697b9f35661f041"

  strings:
    $s1  = "NMI COUNTER FAILURE - Increment!!!!!" fullword wide
    $s2  = "NMI COUNTER FAILURE - decrement!!!!!" fullword wide
    $s3  = "profile - error!!!" fullword wide
    $s4  = "AppCompleted - entered with proc_id %d, socket_type %d, remote_ip %s, remote_port %d, local_ip %s, local_port %d, proto %d, sock" wide
    $s5  = "CheckAppAccess - entered with proc_id %d, proc_path %s, socket_type %d, remote_ip %s, remote_port %d, local_ip %s, local_port %d" wide
    $s6  = "PROCESS NAME:  %s" fullword wide
    $s7  = "  parent process ID = %d" fullword wide
    $s8  = "get computer name" fullword wide
    $s9  = "nCNAMSrvUtility::ObjGetName - nCException Exception caught" fullword wide
    $s10 = "nCNAMSrvUtility :: ObjGetValue - nCException Exception caught " fullword wide
    $s11 = "nCNAMSrvUtility :: ObjGetValueNMI - nCException Exception caught " fullword wide
    $s12 = "nCNAMSrvUtility :: PurgeTable - nCException Exception caught " fullword wide
    $s13 = "method GetSystemInformationWWW" fullword ascii
    $s14 = "NMI_initialize - enter" fullword wide
    $s15 = "NMI_initialize - exit" fullword wide
    $s16 = "NMIInit - exit" fullword wide
    $s17 = "Internal Error. Fail to get name: %s" fullword wide
    $s18 = "Internal Error. Fail to get value: %s" fullword wide
    $s19 = "profile - entered" fullword wide
    $s20 = "Internal Error. GetFPBandwidth failed %s" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}