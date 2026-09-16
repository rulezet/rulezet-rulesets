rule TTP_XOR_WriteProcessMemory_21a7 {
  strings:
    $key_21a7 = { 76 d5 [2] 44 f7 [2] 42 c2 [2] 6c c2 [2] 53 de }

  condition:
    any of them
}