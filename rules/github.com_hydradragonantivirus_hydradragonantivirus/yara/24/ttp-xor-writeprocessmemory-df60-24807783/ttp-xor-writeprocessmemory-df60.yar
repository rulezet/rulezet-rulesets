rule TTP_XOR_WriteProcessMemory_df60 {
  strings:
    $key_df60 = { 88 12 [2] ba 30 [2] bc 05 [2] 92 05 [2] ad 19 }

  condition:
    any of them
}