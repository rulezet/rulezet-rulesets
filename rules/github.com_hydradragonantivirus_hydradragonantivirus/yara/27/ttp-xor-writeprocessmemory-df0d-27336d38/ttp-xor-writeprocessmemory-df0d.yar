rule TTP_XOR_WriteProcessMemory_df0d {
  strings:
    $key_df0d = { 88 7f [2] ba 5d [2] bc 68 [2] 92 68 [2] ad 74 }

  condition:
    any of them
}