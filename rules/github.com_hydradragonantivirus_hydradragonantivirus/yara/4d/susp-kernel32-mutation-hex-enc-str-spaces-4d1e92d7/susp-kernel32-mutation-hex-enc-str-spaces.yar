rule SUSP_kernel32_mutation_hex_enc_str_spaces {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of kernel32 which can be used for lots of evil things"
    date        = "2024-01-24"
    version     = "1.0"
    DaysofYARA  = "24/100"

  strings:
    $kernel32_hex_enc_str_spaces = "6b 65 72 6e 65 6c 33 32" nocase ascii wide

  condition:
    all of them
}