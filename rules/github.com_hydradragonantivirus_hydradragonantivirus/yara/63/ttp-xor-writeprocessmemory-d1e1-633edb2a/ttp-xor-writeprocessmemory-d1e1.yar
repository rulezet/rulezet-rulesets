rule TTP_XOR_WriteProcessMemory_d1e1 {
  strings:
    $key_d1e1 = { 86 93 [2] b4 b1 [2] b2 84 [2] 9c 84 [2] a3 98 }

  condition:
    any of them
}