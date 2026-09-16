rule TTP_XOR_WriteProcessMemory_df63 {
  strings:
    $key_df63 = { 88 11 [2] ba 33 [2] bc 06 [2] 92 06 [2] ad 1a }

  condition:
    any of them
}