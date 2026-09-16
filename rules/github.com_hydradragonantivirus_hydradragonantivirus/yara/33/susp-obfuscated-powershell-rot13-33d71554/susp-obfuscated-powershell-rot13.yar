rule SUSP_Obfuscated_Powershell_rot13 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via rot13"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_rot13 = "cbjrefuryy" nocase ascii wide
    $PowerShell_rot13 = "CbjreFuryy" nocase ascii wide
    $Powershell_rot13 = "Cbjrefuryy" nocase ascii wide

  condition:
    any of them
}