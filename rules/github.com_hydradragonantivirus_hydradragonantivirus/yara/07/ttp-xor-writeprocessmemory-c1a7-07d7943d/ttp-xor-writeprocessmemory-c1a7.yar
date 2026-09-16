rule TTP_XOR_WriteProcessMemory_c1a7 {
  strings:
    $key_c1a7 = { 96 d5 [2] a4 f7 [2] a2 c2 [2] 8c c2 [2] b3 de }

  condition:
    any of them
}