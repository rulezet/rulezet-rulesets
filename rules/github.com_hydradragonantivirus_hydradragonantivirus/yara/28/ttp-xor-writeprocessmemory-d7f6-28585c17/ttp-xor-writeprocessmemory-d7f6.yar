rule TTP_XOR_WriteProcessMemory_d7f6 {
  strings:
    $key_d7f6 = { 80 84 [2] b2 a6 [2] b4 93 [2] 9a 93 [2] a5 8f }

  condition:
    any of them
}