rule TTP_XOR_WriteProcessMemory_df30 {
  strings:
    $key_df30 = { 88 42 [2] ba 60 [2] bc 55 [2] 92 55 [2] ad 49 }

  condition:
    any of them
}