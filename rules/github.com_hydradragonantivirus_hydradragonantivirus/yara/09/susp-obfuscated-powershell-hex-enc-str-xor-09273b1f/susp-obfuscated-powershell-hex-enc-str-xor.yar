rule SUSP_Obfuscated_Powershell_hex_enc_str_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_xor"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_hex_enc_str_xor = "706f7765727368656c6c" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_xor = "506f7765725368656c6c" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_xor = "506f7765727368656c6c" xor(0x01-0xff) ascii wide

  condition:
    any of them
}