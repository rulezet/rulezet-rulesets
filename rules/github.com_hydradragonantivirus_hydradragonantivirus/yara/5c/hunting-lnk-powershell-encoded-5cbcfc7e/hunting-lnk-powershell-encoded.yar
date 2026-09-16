rule Hunting_LNK_powershell_encoded {
  meta:
    author      = "@captainGeech42"
    description = "Look for LNK files that execute PowerShell with a base64 encoded command. Requires yara-x"
    date        = "2024-01-15"
    version     = "1"
    DaysofYARA  = "15/100"
    hash        = "ccbc8330ca084289cb472ad6f22f39e5177ba66119a5bf6f45cd92c28d976799"

  strings:
    $powershell_str1 = "powershell"
    $powershell_str2 = "-e"

  condition:
    uint32(0) == 0x4c << 24 and
    (
      (any of ($powershell_str*) in (uint8(0)..uint8(filesize)))
    )
}