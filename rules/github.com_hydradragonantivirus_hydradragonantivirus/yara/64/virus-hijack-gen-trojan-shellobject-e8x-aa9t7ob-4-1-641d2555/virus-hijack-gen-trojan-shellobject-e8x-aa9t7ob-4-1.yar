rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "082b86566f8bd2622fc23ad3bce3ba633def370b9412db2a38844215f8255920"

  strings:
    $s1  = "!MainThread, sendLoginInfo error, reconnect again" fullword ascii
    $s2  = "TCPConnecting begin, Host:%s, Port: %d" fullword ascii
    $s3  = "Test Failure, Sleep 10-30m!!!" fullword ascii
    $s4  = "Public Encrypt failed" fullword ascii
    $s5  = "Read config error!" fullword ascii
    $s6  = "Test toatl Failure, Sleep 20_50m!!!, totalcount = %d" fullword ascii
    $s7  = "send askey failed" fullword ascii
    $s8  = "- main connect fail!" fullword ascii
    $s9  = "new key buf error!" fullword ascii
    $s10 = "configure data key:%s" fullword ascii
    $s11 = "!WorkThread, select error, Disconnect()" fullword ascii
    $s12 = "TestConnectModeI %d Error!" fullword ascii
    $s13 = "!WorkThread, recv error, Disconnect()" fullword ascii
    $s14 = "--> TCP disconnect end" fullword ascii
    $s15 = "get test connect style: %d" fullword ascii
    $s16 = "!Connect, lpszHost = %s" fullword ascii
    $s17 = "@@<- TCP begin DisConstruct" fullword ascii
    $s18 = "<-- TCP disconnect into" fullword ascii
    $s19 = "<-- TCP disconnect exit" fullword ascii
    $s20 = "@@-- TCP Disconnect in DisConstruct" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}