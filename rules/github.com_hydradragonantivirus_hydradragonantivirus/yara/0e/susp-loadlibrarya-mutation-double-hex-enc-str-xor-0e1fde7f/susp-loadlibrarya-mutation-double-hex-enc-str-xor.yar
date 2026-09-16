rule SUSP_LoadLibraryA_mutation_double_hex_enc_str_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
    date        = "2024-01-25"
    version     = "1.0"
    DaysofYARA  = "25/100"

  strings:
    $LoadLibraryA_double_hex_enc_str_xor = "346336663631363434633639363237323631373237393431" xor(0x01-0xff) ascii wide

  condition:
    all of them
}