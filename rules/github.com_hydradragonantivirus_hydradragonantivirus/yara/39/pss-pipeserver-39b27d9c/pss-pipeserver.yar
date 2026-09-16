rule PSS_Pipeserver {
  meta:
    description = "PSS Pipeserver versions 4.x and 5.x"
    author      = "Geoffrey Alexander <geoff@citizenlab.ca>"
    data        = "2017-07-20"

  strings:
    $u1 = "pss-agent" ascii
    $u2 = "PSS_Agent" ascii
    $u3 = "Agent path too long (>= MAX_PATH)" ascii
    $u4 = "Agent is not running, executing it now\\n" ascii
    $u5 = "Failed to create PssClock!" ascii

    $s1  = "LnkProxy" ascii
    $s2  = "CUSTOMER\\Agent" ascii
    $s3  = "BrowseIPC" ascii
    $s4  = "CustomerConfig is not initialized yet" ascii
    $s5  = "RES_BINARY" ascii
    $s6  = "ipc::security_access::" ascii
    $s7  = "util::Resource::" ascii
    $s8  = "util::System::" ascii
    $s9  = "AgentAdminGlobalEventName" wide
    $s10 = "AgentDummyKillGlobalEventName" wide
    $s11 = "AgentGlobalEventName" wide
    $s12 = "AgentKillGlobalEventName" wide
    $s13 = "AgentPipeServerInitGlobalEventName" wide
    $s14 = "AgentUninstallGlobalEventName" wide
    $s15 = "/M:{0FA12518-0120-0910-A43C-0DAA276D2EA4}" wide
    $s16 = "\\\\.\\pipe\\BrowseIPC" wide
    $s17 = "RES_BINARY" wide
    $s18 = "/{433a-bbaf439-12982d4a-9c27}" wide

  condition:
    uint16(0) == 0x5a4d and 1 of ($u*) and 8 of ($s*)
}