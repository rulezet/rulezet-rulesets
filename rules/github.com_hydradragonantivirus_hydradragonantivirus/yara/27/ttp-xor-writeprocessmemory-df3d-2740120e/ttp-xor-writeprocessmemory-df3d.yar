rule TTP_XOR_WriteProcessMemory_df3d {
  strings:
    $key_df3d = { 88 4f [2] ba 6d [2] bc 58 [2] 92 58 [2] ad 44 }

  condition:
    any of them
}