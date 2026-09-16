rule TTP_XOR_WriteProcessMemory_df73 {
  strings:
    $key_df73 = { 88 01 [2] ba 23 [2] bc 16 [2] 92 16 [2] ad 0a }

  condition:
    any of them
}