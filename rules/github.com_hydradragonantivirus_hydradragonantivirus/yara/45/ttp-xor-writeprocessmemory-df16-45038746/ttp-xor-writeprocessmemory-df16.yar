rule TTP_XOR_WriteProcessMemory_df16 {
  strings:
    $key_df16 = { 88 64 [2] ba 46 [2] bc 73 [2] 92 73 [2] ad 6f }

  condition:
    any of them
}