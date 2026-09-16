rule TTP_XOR_WriteProcessMemory_df9b {
  strings:
    $key_df9b = { 88 e9 [2] ba cb [2] bc fe [2] 92 fe [2] ad e2 }

  condition:
    any of them
}