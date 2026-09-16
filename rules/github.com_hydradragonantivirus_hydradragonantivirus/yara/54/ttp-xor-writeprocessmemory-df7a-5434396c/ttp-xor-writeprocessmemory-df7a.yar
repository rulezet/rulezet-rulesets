rule TTP_XOR_WriteProcessMemory_df7a {
  strings:
    $key_df7a = { 88 08 [2] ba 2a [2] bc 1f [2] 92 1f [2] ad 03 }

  condition:
    any of them
}