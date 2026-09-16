rule TTP_XOR_WriteProcessMemory_df14 {
  strings:
    $key_df14 = { 88 66 [2] ba 44 [2] bc 71 [2] 92 71 [2] ad 6d }

  condition:
    any of them
}