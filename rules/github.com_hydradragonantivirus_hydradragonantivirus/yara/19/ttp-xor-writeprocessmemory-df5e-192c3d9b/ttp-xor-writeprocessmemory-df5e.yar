rule TTP_XOR_WriteProcessMemory_df5e {
  strings:
    $key_df5e = { 88 2c [2] ba 0e [2] bc 3b [2] 92 3b [2] ad 27 }

  condition:
    any of them
}