rule SUSP_Obfuscated_Powershell_hex_enc_str_reversed_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_reversed_b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_hex_enc_str_reversed_b64 = "c6c6568637275677f607" base64 base64wide
    $PowerShell_hex_enc_str_reversed_b64 = "c6c6568635275677f605" base64 base64wide
    $Powershell_hex_enc_str_reversed_b64 = "c6c6568637275677f605" base64 base64wide

  condition:
    any of them
}