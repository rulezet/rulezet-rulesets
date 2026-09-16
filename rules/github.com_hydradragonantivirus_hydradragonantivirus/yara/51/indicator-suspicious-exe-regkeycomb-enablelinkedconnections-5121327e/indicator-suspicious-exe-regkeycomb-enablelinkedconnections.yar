rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_EnableLinkedConnections {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination ensuring mapped drives are available from an elevated prompt or process with UAC enabled. Observed in ransomware"
    strings:
        $r1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide nocase
        $k1 = "EnableLinkedConnections" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}