import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_2_2_Virus_Hijac_274 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aOGzovi_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cd948b968d5923183d00f6c835f7ea94184953af9476acbf6270074c3455761"
    hash2       = "0cfb20dd21bacf59a0d507083e2f8167ef977e8fb8c0ecb0fbc7b88f972537e3"

  strings:
    $s1  = "CServiceUptime::GetHeartbeatInterval: Failed to open key %s - 0x%x" fullword wide
    $s2  = "CServiceUptime::GetHeartbeatInterval: Failed to query key %s - 0x%x" fullword wide
    $s3  = "CServiceUptime::GetHistory: Failed to set default for value %s - 0x%x" fullword wide
    $s4  = "CServiceUptime::UpdateHeartbeat: Failed to open key %s - 0x%x" fullword wide
    $s5  = "CServiceUptime::RecordServiceStop: Failed to open key %s - 0x%x" fullword wide
    $s6  = "CServiceUptime::RecordServiceStart: Failed to open key %s - 0x%x" fullword wide
    $s7  = "CServiceUptime::RecordServiceStart: Failed to set value %s - 0x%x" fullword wide
    $s8  = "CServiceUptime::SetHeartbeatInterval: Failed to open key %s - 0x%x" fullword wide
    $s9  = "Starting event trace in ehSched.exe" fullword wide
    $s10 = "End event trace in ehSched.exe" fullword wide
    $s11 = "CServiceUptime::StartHeartbeatTimer: Failed during SetWaitableTimer - 0x%x" fullword wide
    $s12 = "ehSched:: unable to create hProcessUpEvent" fullword wide
    $s13 = "ehSched:: Failed to get handle to event mediators thread (%08x), exiting" fullword wide
    $s14 = "CResourceMgr::GetIRUser failed to create MCEIRUser 0x%X" fullword wide
    $s15 = "CServiceUptime::GetHeartbeatInterval: %s was out of range. Overriding %d with default value %d" fullword wide
    $s16 = "<description>Windows Media Center Scheduler Service</description>" fullword ascii
    $s17 = "CServiceModule:Install: Failed to configure service SID_TYPE 0x%x" fullword wide
    $s18 = "CServiceModule::Install: Failed to configure service REQUIRED_PRIVLEDGES 0x%x" fullword wide
    $s19 = "ehSched:: event mediator failed to create %s: %08x" fullword wide
    $s20 = "ehSched:: failed to register %s: %08x" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "56bc9adcf5c93d8b8dc9fbe590f176c4" and (8 of them)
    ) or (all of them)
}