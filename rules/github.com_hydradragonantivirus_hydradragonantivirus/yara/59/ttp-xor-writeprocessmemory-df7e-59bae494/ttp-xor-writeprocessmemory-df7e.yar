rule TTP_XOR_WriteProcessMemory_df7e {
  strings:
    $key_df7e = { 88 0c [2] ba 2e [2] bc 1b [2] 92 1b [2] ad 07 }

  condition:
    any of them
}