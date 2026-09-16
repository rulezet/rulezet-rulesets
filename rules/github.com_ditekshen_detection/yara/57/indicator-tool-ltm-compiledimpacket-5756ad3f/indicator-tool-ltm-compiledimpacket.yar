rule INDICATOR_TOOL_LTM_CompiledImpacket {
    meta:
        author = "ditekSHen"
        description = "Detects executables of compiled Impacket's python scripts"
    strings:
        $s1 = "impacket(" fullword ascii
        $s2 = "impacket.dcerpc(" fullword ascii
        $s3 = "impacket.krb5(" fullword ascii
        $s4 = "impacket.smb(" fullword ascii
        $s5 = "impacket.smb3(" fullword ascii
        $s6 = "impacket.winregistry(" fullword ascii
        $s7 = "impacket.ntlm(" fullword ascii
        $m1 = "inspect(" fullword ascii
        $m2 = "pickle(" fullword ascii
        $m3 = "spsexec" fullword ascii
        $m4 = "schecker" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or (3 of ($m*) and 1 of ($s*)))
}