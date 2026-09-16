rule TTP_XOR_WriteProcessMemory_df38 {
  strings:
    $key_df38 = { 88 4a [2] ba 68 [2] bc 5d [2] 92 5d [2] ad 41 }

  condition:
    any of them
}