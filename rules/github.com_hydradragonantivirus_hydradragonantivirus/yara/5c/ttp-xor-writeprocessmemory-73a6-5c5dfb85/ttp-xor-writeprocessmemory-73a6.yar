rule TTP_XOR_WriteProcessMemory_73a6 {
  strings:
    $key_73a6 = { 24 d4 [2] 16 f6 [2] 10 c3 [2] 3e c3 [2] 01 df }

  condition:
    any of them
}