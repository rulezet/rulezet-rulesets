rule TTP_XOR_WriteProcessMemory_df92 {
  strings:
    $key_df92 = { 88 e0 [2] ba c2 [2] bc f7 [2] 92 f7 [2] ad eb }

  condition:
    any of them
}