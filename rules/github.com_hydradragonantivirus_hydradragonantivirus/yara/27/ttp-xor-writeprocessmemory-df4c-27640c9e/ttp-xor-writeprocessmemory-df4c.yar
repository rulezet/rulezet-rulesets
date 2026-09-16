rule TTP_XOR_WriteProcessMemory_df4c {
  strings:
    $key_df4c = { 88 3e [2] ba 1c [2] bc 29 [2] 92 29 [2] ad 35 }

  condition:
    any of them
}