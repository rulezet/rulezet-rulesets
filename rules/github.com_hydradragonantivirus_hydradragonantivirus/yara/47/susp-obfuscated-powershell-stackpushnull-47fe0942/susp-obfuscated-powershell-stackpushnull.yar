rule SUSP_Obfuscated_Powershell_stackpushnull {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpushnull"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_stackpushnull = "hll\x00hrshehpowe" nocase ascii wide
    $PowerShell_stackpushnull = "hll\x00hrShehPowe" nocase ascii wide
    $Powershell_stackpushnull = "hll\x00hrshehPowe" nocase ascii wide

  condition:
    any of them
}