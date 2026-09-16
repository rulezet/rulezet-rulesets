rule TTP_XOR_WriteProcessMemory_df15 {
  strings:
    $key_df15 = { 88 67 [2] ba 45 [2] bc 70 [2] 92 70 [2] ad 6c }

  condition:
    any of them
}