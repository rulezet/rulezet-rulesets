rule TTP_XOR_WriteProcessMemory_df66 {
  strings:
    $key_df66 = { 88 14 [2] ba 36 [2] bc 03 [2] 92 03 [2] ad 1f }

  condition:
    any of them
}