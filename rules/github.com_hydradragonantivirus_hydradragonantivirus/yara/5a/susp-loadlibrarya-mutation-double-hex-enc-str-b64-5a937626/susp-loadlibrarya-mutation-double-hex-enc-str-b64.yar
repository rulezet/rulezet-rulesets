rule SUSP_LoadLibraryA_mutation_double_hex_enc_str_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
    date        = "2024-01-25"
    version     = "1.0"
    DaysofYARA  = "25/100"

  strings:
    $LoadLibraryA_double_hex_enc_str_b64 = "346336663631363434633639363237323631373237393431" base64 base64wide

  condition:
    all of them
}