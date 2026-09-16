rule TTP_XOR_WriteProcessMemory_df58 {
  strings:
    $key_df58 = { 88 2a [2] ba 08 [2] bc 3d [2] 92 3d [2] ad 21 }

  condition:
    any of them
}