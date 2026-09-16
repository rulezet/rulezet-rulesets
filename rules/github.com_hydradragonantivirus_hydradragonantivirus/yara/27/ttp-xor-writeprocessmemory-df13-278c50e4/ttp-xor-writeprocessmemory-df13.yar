rule TTP_XOR_WriteProcessMemory_df13 {
  strings:
    $key_df13 = { 88 61 [2] ba 43 [2] bc 76 [2] 92 76 [2] ad 6a }

  condition:
    any of them
}