rule INDICATOR_TOOL_LTM_LadonExp {
    meta:
        author = "ditekSHen"
        description = "Detect Ladon tool that assists in lateral movement across a network"
    strings:
        $s1 = "txt_cscandll.Text" fullword wide
        $s2 = "CscanWebExpBuild.frmMain.resources" fullword ascii
        $s3 = "= \"$HttpXforwardedFor$\";" ascii
        $s4 = "namespace netscan" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 3 of them
}