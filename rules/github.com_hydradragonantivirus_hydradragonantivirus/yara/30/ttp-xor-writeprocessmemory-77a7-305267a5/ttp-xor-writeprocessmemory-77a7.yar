rule TTP_XOR_WriteProcessMemory_77a7 {
  strings:
    $key_77a7 = { 20 d5 [2] 12 f7 [2] 14 c2 [2] 3a c2 [2] 05 de }

  condition:
    any of them
}