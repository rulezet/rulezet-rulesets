rule TTP_XOR_WriteProcessMemory_51a7 {
  strings:
    $key_51a7 = { 06 d5 [2] 34 f7 [2] 32 c2 [2] 1c c2 [2] 23 de }

  condition:
    any of them
}