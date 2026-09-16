rule SUSP_Obfuscated_Mozilla_hex_enc_str_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "track obfuscated Mozilla strings"
    date        = "2024-02-13"
    version     = "1.0"
    DaysOfYara  = "44/100"

  strings:
    $Mozilla_hex_enc_str_b64 = "4d6f7a696c6c61" base64 base64wide

  condition:
    all of them
}