rule SUSP_Obfuscated_Powershell_stackpushdoublenull {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpushdoublenull"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_stackpushdoublenull = "hll\x00\x00hrshehpowe" nocase ascii wide
    $PowerShell_stackpushdoublenull = "hll\x00\x00hrShehPowe" nocase ascii wide
    $Powershell_stackpushdoublenull = "hll\x00\x00hrshehPowe" nocase ascii wide

  condition:
    any of them
}