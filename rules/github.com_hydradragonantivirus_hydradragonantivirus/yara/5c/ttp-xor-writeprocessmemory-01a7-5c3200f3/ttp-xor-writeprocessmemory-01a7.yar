rule TTP_XOR_WriteProcessMemory_01a7 {
  strings:
    $key_01a7 = { 56 d5 [2] 64 f7 [2] 62 c2 [2] 4c c2 [2] 73 de }

  condition:
    any of them
}