rule TTP_XOR_WriteProcessMemory_1fa7 {
  strings:
    $key_1fa7 = { 48 d5 [2] 7a f7 [2] 7c c2 [2] 52 c2 [2] 6d de }

  condition:
    any of them
}