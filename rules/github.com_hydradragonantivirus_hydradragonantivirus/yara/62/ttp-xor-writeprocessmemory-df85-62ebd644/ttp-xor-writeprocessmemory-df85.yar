rule TTP_XOR_WriteProcessMemory_df85 {
  strings:
    $key_df85 = { 88 f7 [2] ba d5 [2] bc e0 [2] 92 e0 [2] ad fc }

  condition:
    any of them
}