rule TTP_XOR_WriteProcessMemory_d1d4 {
  strings:
    $key_d1d4 = { 86 a6 [2] b4 84 [2] b2 b1 [2] 9c b1 [2] a3 ad }

  condition:
    any of them
}