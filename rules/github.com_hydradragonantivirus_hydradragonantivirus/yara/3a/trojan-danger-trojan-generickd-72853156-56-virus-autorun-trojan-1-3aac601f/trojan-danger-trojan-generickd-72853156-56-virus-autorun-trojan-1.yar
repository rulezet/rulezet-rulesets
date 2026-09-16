rule _Trojan_Danger_Trojan_GenericKD_72853156_56_Virus_Autorun_Trojan_1 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_56.vir, Virus.Autorun_Trojan.GenericKDZ.94942_4.vir, Virus.Autorun_Trojan.GenericKDZ.94942_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f48dc4349b17c5db231be8e38c6e9aa55993614d3ecce977526d872dfe38a50d"
    hash2       = "42856ebb178057d425b0915032faa9243a470593208790861c68cd3115a13240"
    hash3       = "f424124429184fcce5f03de260e2a123484d1943b89552c527f43cf7d593794c"

  strings:
    $x1  = "UseSystemPowerShell - Execute PowerShell using an external process instead of the built-in PowerShell host. Should only be used " wide
    $x2  = "    $wrappedStatements = \"-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -InputFormat Text -OutputFormat Text -Enco" ascii
    $x3  = "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command \"{0}\"" fullword wide
    $x4  = "  source = \"--name='' --source='' --user='' --password='' --priority= --bypass-proxy --allow-self-service -?\" + $allcommands" fullword ascii
    $x5  = " * ChocolateyResponseTimeout - How long to wait for a download to complete? Set by config `commandExecutionTimeoutSeconds` (CHEC" wide
    $x6  = "# Install-ChocolateyShortcut -shortcutFilePath \"<path>\" -targetPath \"<path>\" [-workDirectory \"C:\\\" -arguments \"C:\\test." wide
    $x7  = " * ChocolateyEnvironmentDebug - Was `--debug` passed? If using the built-in PowerShell host, this is always true (but only logs " wide
    $x8  = " * ChocolateyEnvironmentVerbose - Was `--verbose` passed? If using the built-in PowerShell host, this is always true (but only l" wide
    $x9  = "powershell -NoProfile -ExecutionPolicy unrestricted -Command \"\"& `'$psFileFullPath`'  %*\"\"\"| Out-File $packageBatchFileName" ascii
    $x10 = "powershell -NoProfile -ExecutionPolicy unrestricted -Command \"\"& `'$psFileFullPath`'  %*\"\"\"| Out-File $packageBatchFileName" ascii
    $x11 = "  Write-Debug \"Error handling check: `'Get-ItemProperty`' fails if a registry key is encoded incorrectly.\"" fullword ascii
    $x12 = "    \"%WinDir%\\System32\\Reg\" QUERY \"%~1\" /v \"%~2\" > \"%TEMP%\\_envset.tmp\" 2>NUL" fullword ascii
    $x13 = "  list = \"--lo --id-only --pre --exact --by-id-only --id-starts-with --detailed --approved-only --not-broken --source='' --user" ascii
    $x14 = " * ChocolateyInstallArgumentsSensitive - Encrypted arguments passed from command line `--install-arguments-sensitive` that are n" wide
    $x15 = "Chocolatey detected you are not running from an elevated command shell" fullword wide
    $x16 = "CommandExecutionTimeout (in seconds) - The time to allow a command to finish before timing out. Overrides the default execution " wide
    $x17 = "# Posh-Git License - https://github.com/dahlbyk/posh-git/blob/1941da2472eb668cde2d6a5fc921d5043a024386/LICENSE.txt" fullword ascii
    $x18 = "## Some code from http://stackoverflow.com/questions/265339/whats-the-best-way-to-automate-secure-ftp-in-powershell" fullword ascii
    $x19 = "    $wrappedStatements = \"-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -InputFormat Text -OutputFormat Text -Enco" ascii
    $s20 = "    del /f /q \"%TEMP%\\_envget.tmp\" 2>nul" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*))
    ) or (all of them)
}