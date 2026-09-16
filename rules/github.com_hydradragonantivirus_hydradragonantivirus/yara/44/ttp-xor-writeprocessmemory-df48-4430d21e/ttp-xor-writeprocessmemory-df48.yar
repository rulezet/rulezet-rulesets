rule TTP_XOR_WriteProcessMemory_df48 {
  strings:
    $key_df48 = { 88 3a [2] ba 18 [2] bc 2d [2] 92 2d [2] ad 31 }

  condition:
    any of them
}