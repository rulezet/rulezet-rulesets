rule TTP_XOR_WriteProcessMemory_3fa7 {
  strings:
    $key_3fa7 = { 68 d5 [2] 5a f7 [2] 5c c2 [2] 72 c2 [2] 4d de }

  condition:
    any of them
}