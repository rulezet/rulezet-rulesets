rule SUSP_Obfuscated_Powershell_rot13_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via rot13_b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_rot13_b64 = "cbjrefuryy" base64 base64wide
    $PowerShell_rot13_b64 = "CbjreFuryy" base64 base64wide
    $Powershell_rot13_b64 = "Cbjrefuryy" base64 base64wide

  condition:
    any of them
}