rule TTP_XOR_WriteProcessMemory_5fa6 {
  strings:
    $key_5fa6 = { 08 d4 [2] 3a f6 [2] 3c c3 [2] 12 c3 [2] 2d df }

  condition:
    any of them
}