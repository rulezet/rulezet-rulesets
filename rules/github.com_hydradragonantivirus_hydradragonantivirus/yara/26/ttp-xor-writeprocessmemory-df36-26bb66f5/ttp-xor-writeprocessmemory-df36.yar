rule TTP_XOR_WriteProcessMemory_df36 {
  strings:
    $key_df36 = { 88 44 [2] ba 66 [2] bc 53 [2] 92 53 [2] ad 4f }

  condition:
    any of them
}