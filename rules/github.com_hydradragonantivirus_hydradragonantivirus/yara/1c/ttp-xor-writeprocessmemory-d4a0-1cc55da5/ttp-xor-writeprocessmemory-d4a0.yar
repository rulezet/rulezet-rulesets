rule TTP_XOR_WriteProcessMemory_d4a0 {
  strings:
    $key_d4a0 = { 83 d2 [2] b1 f0 [2] b7 c5 [2] 99 c5 [2] a6 d9 }

  condition:
    any of them
}