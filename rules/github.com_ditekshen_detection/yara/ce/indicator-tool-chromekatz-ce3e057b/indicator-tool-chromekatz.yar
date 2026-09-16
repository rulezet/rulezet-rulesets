rule INDICATOR_TOOL_ChromeKatz {
    meta:
        author = "ditekshen"
        description = "Detects ChromeKatz: CookieKatz and CredentialKatz"
    strings:
        $s1 = "\\include\\xmemory" ascii wide
        $s2 = "targetBrowser" ascii
        $s3 = "thirdPattern" ascii
        $s4 = "isBrowserWow64" ascii
        $s5 = "wcscpy_s(memory, size_in_elements, string)" fullword wide
        $s6 = "hChrome" fullword ascii
        $t1 = "szCookieMonster" fullword ascii
        $t2 = "szPasswordReuseDetectorInstances" fullword ascii
    condition: 
        uint16(0) == 0x5a4d and 6 of them
}