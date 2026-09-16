rule TTP_XOR_WriteProcessMemory_df01 {
  strings:
    $key_df01 = { 88 73 [2] ba 51 [2] bc 64 [2] 92 64 [2] ad 78 }

  condition:
    any of them
}