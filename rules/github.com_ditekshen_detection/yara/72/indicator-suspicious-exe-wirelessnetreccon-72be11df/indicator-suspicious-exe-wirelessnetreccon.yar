rule INDICATOR_SUSPICIOUS_EXE_WirelessNetReccon {
    meta:
        author = "ditekSHen"
        description = "Detects executables with interest in wireless interface using netsh"
    strings:
        $s1 = "netsh wlan show profile" ascii wide nocase
        $s2 = "netsh wlan show profile name=" ascii wide nocase
        $s3 = "netsh wlan show networks mode=bssid" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and all of them
}