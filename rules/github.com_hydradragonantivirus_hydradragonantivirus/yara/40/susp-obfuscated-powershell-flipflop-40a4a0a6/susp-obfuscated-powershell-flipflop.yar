rule SUSP_Obfuscated_Powershell_flipflop {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via flipflop"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_flipflop = "opewsrehll" nocase ascii wide
    $PowerShell_flipflop = "oPewSrehll" nocase ascii wide
    $Powershell_flipflop = "oPewsrehll" nocase ascii wide

  condition:
    any of them
}