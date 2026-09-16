rule TTP_XOR_WriteProcessMemory_df90 {
  strings:
    $key_df90 = { 88 e2 [2] ba c0 [2] bc f5 [2] 92 f5 [2] ad e9 }

  condition:
    any of them
}