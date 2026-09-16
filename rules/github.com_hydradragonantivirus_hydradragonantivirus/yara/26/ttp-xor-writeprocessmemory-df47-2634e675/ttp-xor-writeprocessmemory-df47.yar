rule TTP_XOR_WriteProcessMemory_df47 {
  strings:
    $key_df47 = { 88 35 [2] ba 17 [2] bc 22 [2] 92 22 [2] ad 3e }

  condition:
    any of them
}