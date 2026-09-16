rule TTP_XOR_WriteProcessMemory_d7a0 {
  strings:
    $key_d7a0 = { 80 d2 [2] b2 f0 [2] b4 c5 [2] 9a c5 [2] a5 d9 }

  condition:
    any of them
}