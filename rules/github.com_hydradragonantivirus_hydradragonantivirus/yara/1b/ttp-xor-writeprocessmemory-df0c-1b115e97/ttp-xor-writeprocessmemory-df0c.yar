rule TTP_XOR_WriteProcessMemory_df0c {
  strings:
    $key_df0c = { 88 7e [2] ba 5c [2] bc 69 [2] 92 69 [2] ad 75 }

  condition:
    any of them
}