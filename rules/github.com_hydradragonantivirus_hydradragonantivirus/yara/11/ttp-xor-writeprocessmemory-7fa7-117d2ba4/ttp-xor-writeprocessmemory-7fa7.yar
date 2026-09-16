rule TTP_XOR_WriteProcessMemory_7fa7 {
  strings:
    $key_7fa7 = { 28 d5 [2] 1a f7 [2] 1c c2 [2] 32 c2 [2] 0d de }

  condition:
    any of them
}