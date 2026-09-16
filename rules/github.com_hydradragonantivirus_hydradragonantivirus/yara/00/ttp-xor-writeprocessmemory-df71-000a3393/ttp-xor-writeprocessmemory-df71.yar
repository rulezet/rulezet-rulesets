rule TTP_XOR_WriteProcessMemory_df71 {
  strings:
    $key_df71 = { 88 03 [2] ba 21 [2] bc 14 [2] 92 14 [2] ad 08 }

  condition:
    any of them
}