rule TTP_XOR_WriteProcessMemory_42a7 {
  strings:
    $key_42a7 = { 15 d5 [2] 27 f7 [2] 21 c2 [2] 0f c2 [2] 30 de }

  condition:
    any of them
}