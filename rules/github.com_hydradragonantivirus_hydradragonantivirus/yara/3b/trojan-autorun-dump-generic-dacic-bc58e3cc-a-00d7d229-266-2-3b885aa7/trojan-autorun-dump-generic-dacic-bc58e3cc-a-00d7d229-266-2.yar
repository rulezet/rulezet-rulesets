rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_266_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_266_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36b057fd0a44652f98ea54100f4f485ee743bd00b52400937fbd976a346d3192"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "ExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:s" ascii
    $s3 = " Install System v2.51</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><request" ascii
    $s4 = "s-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supportedOS Id=\"{e" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}