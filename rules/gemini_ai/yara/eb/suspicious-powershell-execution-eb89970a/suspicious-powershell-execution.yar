rule Suspicious_PowerShell_Execution {
    meta:
        description = "Detects obfuscated or hidden PowerShell execution commands"
        author = "Security Analyst" 
        uuid = "wdh37dw3hdhi2e9jwqjeq3qwisao"
        severity = "Medium"

    strings:
        $ps = "powershell" ascii nocase
        $enc = "-EncodedCommand" ascii nocase
        $nop = "-NoProfile" ascii nocase
        $win = "-WindowStyle Hidden" ascii nocase

    condition:
        $ps and 2 of ($enc, $nop, $win)
}