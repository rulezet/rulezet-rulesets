import "pe"
rule _Virus_Hooker_Trojan_GenericKD_72587580_2_Virus_Infector_Gen_Tro_398 {
  meta:
    description = "datamaliciousorder - from files Virus.Hooker_Trojan.GenericKD.72587580_2.vir, Virus.Infector_Gen.Trojan.Malware.Lq3@aunLb5ni_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "625fa4f0c545b1dd9aaa29f039a1607f5f12dfa0be04154a79bfb09609849e9b"
    hash2       = "a316d2edeae0147ec627ae5d020170e6666f5b8f454f703c611cf00983ae1deb"

  strings:
    $s1  = "%s started with PID: %d, integrity level: %d and command line: \"%s\"." fullword wide
    $s2  = "%s with PID: %d. The remote shutdown thread is exiting. Error code: %x." fullword wide
    $s3  = "%s with PID: %d. The remote shutdown thread was signaled on handle: %x." fullword wide
    $s4  = "%s with PID: %d. The remote shutdown thread has started." fullword wide
    $s5  = "%s with PID: %d has shutdown all services. Error code: %x." fullword wide
    $s6  = "%s with PID: %d has started the automatic services. Error code: %x." fullword wide
    $s7  = " spawn a new instance and" fullword wide
    $s8  = "%s with PID: %d is done waiting and will resume operation." fullword wide
    $s9  = "%s with PID: %d is exiting. Error code: %x." fullword wide
    $s10 = "Solution Activation User Interface" fullword wide
    $s11 = "%s with PID: %d was requested to%s shutdown." fullword wide
    $s12 = "%s with PID: %d waiting for the previous instance to cleanup." fullword wide
    $s13 = "%s with PID: %d was reacting to power broadcast event: %x. Error code: %x." fullword wide
    $s14 = "%s with PID: %d will exit because the required minimum CLR version was not found." fullword wide
    $s15 = "%s with PID: %d will exit because another instance was found running." fullword wide
    $s16 = "Resetting \"safe to connect\" event." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "aae410db5a351d384de2e35faf59497e" and (8 of them)
    ) or (all of them)
}