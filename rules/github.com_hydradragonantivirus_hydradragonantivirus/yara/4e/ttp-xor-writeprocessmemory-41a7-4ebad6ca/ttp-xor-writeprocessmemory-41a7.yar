rule TTP_XOR_WriteProcessMemory_41a7 {
  strings:
    $key_41a7 = { 16 d5 [2] 24 f7 [2] 22 c2 [2] 0c c2 [2] 33 de }

  condition:
    any of them
}