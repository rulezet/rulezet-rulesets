rule TTP_XOR_WriteProcessMemory_df3c {
  strings:
    $key_df3c = { 88 4e [2] ba 6c [2] bc 59 [2] 92 59 [2] ad 45 }

  condition:
    any of them
}