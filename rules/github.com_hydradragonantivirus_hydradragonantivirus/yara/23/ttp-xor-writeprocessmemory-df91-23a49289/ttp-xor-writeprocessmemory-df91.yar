rule TTP_XOR_WriteProcessMemory_df91 {
  strings:
    $key_df91 = { 88 e3 [2] ba c1 [2] bc f4 [2] 92 f4 [2] ad e8 }

  condition:
    any of them
}