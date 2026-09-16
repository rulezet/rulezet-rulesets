rule SUSP_Obfuscated_Powershell_hex_enc_str_reversed {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_reversed"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_hex_enc_str_reversed = "c6c6568637275677f607" nocase ascii wide
    $PowerShell_hex_enc_str_reversed = "c6c6568635275677f605" nocase ascii wide
    $Powershell_hex_enc_str_reversed = "c6c6568637275677f605" nocase ascii wide

  condition:
    any of them
}