rule SUSP_Obfuscated_Powershell_fallchill_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via fallchill_xor"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_fallchill_xor = "kldvihsvoo" xor(0x01-0xff) ascii wide
    $PowerShell_fallchill_xor = "PldviSsvoo" xor(0x01-0xff) ascii wide
    $Powershell_fallchill_xor = "Pldvihsvoo" xor(0x01-0xff) ascii wide

  condition:
    any of them
}