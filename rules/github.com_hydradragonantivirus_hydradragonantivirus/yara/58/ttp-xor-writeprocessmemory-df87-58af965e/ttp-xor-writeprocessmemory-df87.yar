rule TTP_XOR_WriteProcessMemory_df87 {
  strings:
    $key_df87 = { 88 f5 [2] ba d7 [2] bc e2 [2] 92 e2 [2] ad fe }

  condition:
    any of them
}