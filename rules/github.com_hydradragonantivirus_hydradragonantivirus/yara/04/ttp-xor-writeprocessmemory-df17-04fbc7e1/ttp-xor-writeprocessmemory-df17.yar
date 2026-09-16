rule TTP_XOR_WriteProcessMemory_df17 {
  strings:
    $key_df17 = { 88 65 [2] ba 47 [2] bc 72 [2] 92 72 [2] ad 6e }

  condition:
    any of them
}