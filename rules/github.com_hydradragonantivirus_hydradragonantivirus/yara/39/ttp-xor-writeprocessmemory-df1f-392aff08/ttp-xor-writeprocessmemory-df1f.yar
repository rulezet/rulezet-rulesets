rule TTP_XOR_WriteProcessMemory_df1f {
  strings:
    $key_df1f = { 88 6d [2] ba 4f [2] bc 7a [2] 92 7a [2] ad 66 }

  condition:
    any of them
}