rule SUSP_Obfuscated_Powershell_hex_enc_str_b64_enc_str {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_b64_enc_str"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_hex_enc_str_b64_enc_str = "NzA2Zjc3NjU3MjczNjg2NTZjNmM=" nocase ascii wide
    $PowerShell_hex_enc_str_b64_enc_str = "NTA2Zjc3NjU3MjUzNjg2NTZjNmM=" nocase ascii wide
    $Powershell_hex_enc_str_b64_enc_str = "NTA2Zjc3NjU3MjczNjg2NTZjNmM=" nocase ascii wide

  condition:
    any of them
}