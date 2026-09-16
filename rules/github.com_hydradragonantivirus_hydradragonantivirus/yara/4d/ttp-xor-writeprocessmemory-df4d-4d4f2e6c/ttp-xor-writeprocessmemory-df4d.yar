rule TTP_XOR_WriteProcessMemory_df4d {
  strings:
    $key_df4d = { 88 3f [2] ba 1d [2] bc 28 [2] 92 28 [2] ad 34 }

  condition:
    any of them
}