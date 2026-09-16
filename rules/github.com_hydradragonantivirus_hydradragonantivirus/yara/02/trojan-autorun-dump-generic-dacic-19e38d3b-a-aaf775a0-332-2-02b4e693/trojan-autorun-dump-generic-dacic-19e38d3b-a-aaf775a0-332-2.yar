rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_332_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_332_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc076806fcdadff211dd630b9ae8738636d18089fe3044c1e2539483170938f2"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "ExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:s" ascii
    $s3 = "nstall System v3.06.1</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><request" ascii
    $s4 = "s-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}