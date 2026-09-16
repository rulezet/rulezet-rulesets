rule INDICATOR_TOOL_KrbRelay {
    meta:
        author = "ditekshen"
        description = "Detects KrbRelay"
    strings:
        $s1 = "System.Collections.Generic.IEnumerable<System.IntPtr>.GetEnumerator" fullword ascii
        $s2 = "System.Collections.Generic.IEnumerator<System.IntPtr>.get_Current" fullword ascii
        $s3 = "GetProcessIdFromIPid" fullword ascii
        $g1 = "hello.stg" fullword wide
        $g2 = "DSInternals.Common" fullword ascii
        $g3 = "C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_7b3eed059f4c3e41\\Amd64\\UNIDRV.DLL" fullword wide
        $g4 = "C:\\Windows\\System32\\kernelbase.dll" fullword wide
        $g5 = "get_UnsupportedSecretEncryptionType" fullword ascii
        $g6 = "CoInitializeSecurity Error: 0x{0:X8}. Exploit will fail." fullword wide
        $g7 = "AuthnSvc: {0} - PrincName: {1}" fullword wide
    condition: 
        uint16(0) == 0x5a4d and ((all of ($s*) and 4 of ($g*)) or (7 of them))
}