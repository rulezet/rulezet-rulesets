rule TTP_XOR_WriteProcessMemory_df5f {
  strings:
    $key_df5f = { 88 2d [2] ba 0f [2] bc 3a [2] 92 3a [2] ad 26 }

  condition:
    any of them
}