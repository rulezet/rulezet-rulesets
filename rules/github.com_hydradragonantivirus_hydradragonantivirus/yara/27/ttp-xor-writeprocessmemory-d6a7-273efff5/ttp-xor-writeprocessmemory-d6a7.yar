rule TTP_XOR_WriteProcessMemory_d6a7 {
  strings:
    $key_d6a7 = { 81 d5 [2] b3 f7 [2] b5 c2 [2] 9b c2 [2] a4 de }

  condition:
    any of them
}