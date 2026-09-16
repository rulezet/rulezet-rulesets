rule TTP_XOR_WriteProcessMemory_df41 {
  strings:
    $key_df41 = { 88 33 [2] ba 11 [2] bc 24 [2] 92 24 [2] ad 38 }

  condition:
    any of them
}