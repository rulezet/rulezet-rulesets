rule TTP_XOR_WriteProcessMemory_d1f6 {
  strings:
    $key_d1f6 = { 86 84 [2] b4 a6 [2] b2 93 [2] 9c 93 [2] a3 8f }

  condition:
    any of them
}