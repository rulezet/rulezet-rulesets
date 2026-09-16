rule TTP_XOR_WriteProcessMemory_df4b {
  strings:
    $key_df4b = { 88 39 [2] ba 1b [2] bc 2e [2] 92 2e [2] ad 32 }

  condition:
    any of them
}