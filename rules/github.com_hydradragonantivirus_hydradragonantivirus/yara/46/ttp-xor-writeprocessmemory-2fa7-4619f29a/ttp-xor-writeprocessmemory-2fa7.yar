rule TTP_XOR_WriteProcessMemory_2fa7 {
  strings:
    $key_2fa7 = { 78 d5 [2] 4a f7 [2] 4c c2 [2] 62 c2 [2] 5d de }

  condition:
    any of them
}