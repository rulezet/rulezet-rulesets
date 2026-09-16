rule TTP_XOR_WriteProcessMemory_df0b {
  strings:
    $key_df0b = { 88 79 [2] ba 5b [2] bc 6e [2] 92 6e [2] ad 72 }

  condition:
    any of them
}