rule SUSP_Obfuscated_Mozilla_url_encoded_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "track obfuscated Mozilla strings"
    date        = "2024-02-13"
    version     = "1.0"
    DaysOfYara  = "44/100"

  strings:
    $Mozilla_url_encoded_xor = "4d%6f%7a%69%6c%6c%61" xor(0x01-0xff) ascii wide

  condition:
    all of them
}