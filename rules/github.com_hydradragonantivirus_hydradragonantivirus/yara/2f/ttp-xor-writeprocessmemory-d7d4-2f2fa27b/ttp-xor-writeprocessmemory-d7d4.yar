rule TTP_XOR_WriteProcessMemory_d7d4 {
  strings:
    $key_d7d4 = { 80 a6 [2] b2 84 [2] b4 b1 [2] 9a b1 [2] a5 ad }

  condition:
    any of them
}