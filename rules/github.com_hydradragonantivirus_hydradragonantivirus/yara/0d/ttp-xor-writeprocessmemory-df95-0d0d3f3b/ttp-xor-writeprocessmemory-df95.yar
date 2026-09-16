rule TTP_XOR_WriteProcessMemory_df95 {
  strings:
    $key_df95 = { 88 e7 [2] ba c5 [2] bc f0 [2] 92 f0 [2] ad ec }

  condition:
    any of them
}