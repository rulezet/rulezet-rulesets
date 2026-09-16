rule TTP_XOR_WriteProcessMemory_df0f {
  strings:
    $key_df0f = { 88 7d [2] ba 5f [2] bc 6a [2] 92 6a [2] ad 76 }

  condition:
    any of them
}