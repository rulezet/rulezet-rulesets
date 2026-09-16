rule TTP_XOR_WriteProcessMemory_df5a {
  strings:
    $key_df5a = { 88 28 [2] ba 0a [2] bc 3f [2] 92 3f [2] ad 23 }

  condition:
    any of them
}