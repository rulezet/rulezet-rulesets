rule TTP_XOR_WriteProcessMemory_df4e {
  strings:
    $key_df4e = { 88 3c [2] ba 1e [2] bc 2b [2] 92 2b [2] ad 37 }

  condition:
    any of them
}