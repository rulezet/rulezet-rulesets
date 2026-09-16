rule SUSP_Obfuscated_Powershell_reverse_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via reverse_b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_reverse_b64 = "llehsrewop" base64 base64wide
    $PowerShell_reverse_b64 = "llehSrewoP" base64 base64wide
    $Powershell_reverse_b64 = "llehsrewoP" base64 base64wide

  condition:
    any of them
}