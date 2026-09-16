rule TTP_XOR_WriteProcessMemory_df04 {
  strings:
    $key_df04 = { 88 76 [2] ba 54 [2] bc 61 [2] 92 61 [2] ad 7d }

  condition:
    any of them
}