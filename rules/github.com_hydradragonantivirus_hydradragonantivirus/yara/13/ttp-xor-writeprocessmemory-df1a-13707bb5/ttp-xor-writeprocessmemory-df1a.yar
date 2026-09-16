rule TTP_XOR_WriteProcessMemory_df1a {
  strings:
    $key_df1a = { 88 68 [2] ba 4a [2] bc 7f [2] 92 7f [2] ad 63 }

  condition:
    any of them
}