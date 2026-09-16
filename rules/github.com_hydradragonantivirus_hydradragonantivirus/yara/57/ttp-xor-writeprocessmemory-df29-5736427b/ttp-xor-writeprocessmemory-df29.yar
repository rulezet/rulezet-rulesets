rule TTP_XOR_WriteProcessMemory_df29 {
  strings:
    $key_df29 = { 88 5b [2] ba 79 [2] bc 4c [2] 92 4c [2] ad 50 }

  condition:
    any of them
}