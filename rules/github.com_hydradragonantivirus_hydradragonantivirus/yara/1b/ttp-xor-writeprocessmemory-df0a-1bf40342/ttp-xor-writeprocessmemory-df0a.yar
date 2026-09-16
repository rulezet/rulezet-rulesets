rule TTP_XOR_WriteProcessMemory_df0a {
  strings:
    $key_df0a = { 88 78 [2] ba 5a [2] bc 6f [2] 92 6f [2] ad 73 }

  condition:
    any of them
}