rule TTP_XOR_WriteProcessMemory_d0b1 {
  strings:
    $key_d0b1 = { 87 c3 [2] b5 e1 [2] b3 d4 [2] 9d d4 [2] a2 c8 }

  condition:
    any of them
}