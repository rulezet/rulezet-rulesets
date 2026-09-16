rule SUSP_kernel32_mutation_double_hex_enc_str_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of kernel32 which can be used for lots of evil things"
    date        = "2024-01-24"
    version     = "1.0"
    DaysofYARA  = "24/100"

  strings:
    $kernel32_double_hex_enc_str_xor = "36623635373236653635366333333332" xor(0x01-0xff) ascii wide

  condition:
    all of them
}