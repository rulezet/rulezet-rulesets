rule TTP_XOR_WriteProcessMemory_27a7 {
  strings:
    $key_27a7 = { 70 d5 [2] 42 f7 [2] 44 c2 [2] 6a c2 [2] 55 de }

  condition:
    any of them
}