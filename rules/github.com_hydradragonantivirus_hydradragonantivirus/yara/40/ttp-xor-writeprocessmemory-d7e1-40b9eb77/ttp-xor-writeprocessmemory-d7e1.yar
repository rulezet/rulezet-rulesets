rule TTP_XOR_WriteProcessMemory_d7e1 {
  strings:
    $key_d7e1 = { 80 93 [2] b2 b1 [2] b4 84 [2] 9a 84 [2] a5 98 }

  condition:
    any of them
}