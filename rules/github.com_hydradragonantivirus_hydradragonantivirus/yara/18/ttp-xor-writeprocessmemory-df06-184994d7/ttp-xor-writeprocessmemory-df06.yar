rule TTP_XOR_WriteProcessMemory_df06 {
  strings:
    $key_df06 = { 88 74 [2] ba 56 [2] bc 63 [2] 92 63 [2] ad 7f }

  condition:
    any of them
}