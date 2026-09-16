rule TTP_XOR_WriteProcessMemory_df02 {
  strings:
    $key_df02 = { 88 70 [2] ba 52 [2] bc 67 [2] 92 67 [2] ad 7b }

  condition:
    any of them
}