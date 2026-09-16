rule TTP_XOR_WriteProcessMemory_df3a {
  strings:
    $key_df3a = { 88 48 [2] ba 6a [2] bc 5f [2] 92 5f [2] ad 43 }

  condition:
    any of them
}