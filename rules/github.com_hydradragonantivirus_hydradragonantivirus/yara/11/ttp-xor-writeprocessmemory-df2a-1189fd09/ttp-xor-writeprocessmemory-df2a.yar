rule TTP_XOR_WriteProcessMemory_df2a {
  strings:
    $key_df2a = { 88 58 [2] ba 7a [2] bc 4f [2] 92 4f [2] ad 53 }

  condition:
    any of them
}