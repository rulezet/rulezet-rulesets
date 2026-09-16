rule SUSP_Obfuscated_Powershell_decimal_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_decimal_b64 = "112 111 119 101 114 115 104 101 108 108" base64 base64wide
    $PowerShell_decimal_b64 = "80 111 119 101 114 83 104 101 108 108" base64 base64wide
    $Powershell_decimal_b64 = "80 111 119 101 114 115 104 101 108 108" base64 base64wide

  condition:
    any of them
}