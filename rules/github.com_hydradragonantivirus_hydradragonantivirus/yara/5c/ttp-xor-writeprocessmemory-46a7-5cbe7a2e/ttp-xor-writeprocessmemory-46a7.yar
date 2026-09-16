rule TTP_XOR_WriteProcessMemory_46a7 {
  strings:
    $key_46a7 = { 11 d5 [2] 23 f7 [2] 25 c2 [2] 0b c2 [2] 34 de }

  condition:
    any of them
}