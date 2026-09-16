rule TTP_XOR_WriteProcessMemory_df56 {
  strings:
    $key_df56 = { 88 24 [2] ba 06 [2] bc 33 [2] 92 33 [2] ad 2f }

  condition:
    any of them
}