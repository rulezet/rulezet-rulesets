rule TTP_XOR_WriteProcessMemory_6fa7 {
  strings:
    $key_6fa7 = { 38 d5 [2] 0a f7 [2] 0c c2 [2] 22 c2 [2] 1d de }

  condition:
    any of them
}