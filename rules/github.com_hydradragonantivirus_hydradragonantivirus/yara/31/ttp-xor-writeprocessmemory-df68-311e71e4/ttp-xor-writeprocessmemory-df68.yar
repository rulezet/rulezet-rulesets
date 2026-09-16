rule TTP_XOR_WriteProcessMemory_df68 {
  strings:
    $key_df68 = { 88 1a [2] ba 38 [2] bc 0d [2] 92 0d [2] ad 11 }

  condition:
    any of them
}