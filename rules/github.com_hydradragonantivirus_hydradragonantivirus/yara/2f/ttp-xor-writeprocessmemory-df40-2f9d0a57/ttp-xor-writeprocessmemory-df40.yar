rule TTP_XOR_WriteProcessMemory_df40 {
  strings:
    $key_df40 = { 88 32 [2] ba 10 [2] bc 25 [2] 92 25 [2] ad 39 }

  condition:
    any of them
}