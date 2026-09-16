rule TTP_XOR_WriteProcessMemory_d6f6 {
  strings:
    $key_d6f6 = { 81 84 [2] b3 a6 [2] b5 93 [2] 9b 93 [2] a4 8f }

  condition:
    any of them
}