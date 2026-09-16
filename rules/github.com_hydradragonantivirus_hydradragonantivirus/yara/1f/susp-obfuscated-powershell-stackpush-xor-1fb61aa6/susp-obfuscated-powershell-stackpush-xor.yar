rule SUSP_Obfuscated_Powershell_stackpush_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpush_xor"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_stackpush_xor = "hllhrshehpowe" xor(0x01-0xff) ascii wide
    $PowerShell_stackpush_xor = "hllhrShehPowe" xor(0x01-0xff) ascii wide
    $Powershell_stackpush_xor = "hllhrshehPowe" xor(0x01-0xff) ascii wide

  condition:
    any of them
}