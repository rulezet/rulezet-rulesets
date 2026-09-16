rule TTP_XOR_WriteProcessMemory_df12 {
  strings:
    $key_df12 = { 88 60 [2] ba 42 [2] bc 77 [2] 92 77 [2] ad 6b }

  condition:
    any of them
}