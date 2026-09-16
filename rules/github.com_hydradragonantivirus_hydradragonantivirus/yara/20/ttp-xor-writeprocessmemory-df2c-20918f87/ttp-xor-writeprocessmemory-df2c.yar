rule TTP_XOR_WriteProcessMemory_df2c {
  strings:
    $key_df2c = { 88 5e [2] ba 7c [2] bc 49 [2] 92 49 [2] ad 55 }

  condition:
    any of them
}