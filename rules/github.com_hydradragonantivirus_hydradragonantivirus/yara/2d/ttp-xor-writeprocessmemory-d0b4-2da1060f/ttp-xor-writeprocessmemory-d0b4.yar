rule TTP_XOR_WriteProcessMemory_d0b4 {
  strings:
    $key_d0b4 = { 87 c6 [2] b5 e4 [2] b3 d1 [2] 9d d1 [2] a2 cd }

  condition:
    any of them
}