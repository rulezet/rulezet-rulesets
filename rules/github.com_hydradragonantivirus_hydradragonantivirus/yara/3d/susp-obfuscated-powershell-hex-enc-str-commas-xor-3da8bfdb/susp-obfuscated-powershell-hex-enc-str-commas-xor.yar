rule SUSP_Obfuscated_Powershell_hex_enc_str_commas_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_commas_xor"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_hex_enc_str_commas_xor = "70,6f,77,65,72,73,68,65,6c,6c" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_commas_xor = "50,6f,77,65,72,53,68,65,6c,6c" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_commas_xor = "50,6f,77,65,72,73,68,65,6c,6c" xor(0x01-0xff) ascii wide

  condition:
    any of them
}