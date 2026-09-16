rule SUSP_Obfuscated_Powershell_fallchill_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via fallchill_b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_fallchill_b64 = "kldvihsvoo" base64 base64wide
    $PowerShell_fallchill_b64 = "PldviSsvoo" base64 base64wide
    $Powershell_fallchill_b64 = "Pldvihsvoo" base64 base64wide

  condition:
    any of them
}