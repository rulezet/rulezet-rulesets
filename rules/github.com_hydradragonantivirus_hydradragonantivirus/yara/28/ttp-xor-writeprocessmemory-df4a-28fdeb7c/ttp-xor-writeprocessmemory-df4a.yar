rule TTP_XOR_WriteProcessMemory_df4a {
  strings:
    $key_df4a = { 88 38 [2] ba 1a [2] bc 2f [2] 92 2f [2] ad 33 }

  condition:
    any of them
}