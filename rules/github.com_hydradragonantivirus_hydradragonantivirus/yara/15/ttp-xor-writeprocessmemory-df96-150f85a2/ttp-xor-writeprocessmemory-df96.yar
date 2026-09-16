rule TTP_XOR_WriteProcessMemory_df96 {
  strings:
    $key_df96 = { 88 e4 [2] ba c6 [2] bc f3 [2] 92 f3 [2] ad ef }

  condition:
    any of them
}