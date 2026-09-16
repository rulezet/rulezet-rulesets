rule TTP_XOR_WriteProcessMemory_d0a0 {
  strings:
    $key_d0a0 = { 87 d2 [2] b5 f0 [2] b3 c5 [2] 9d c5 [2] a2 d9 }

  condition:
    any of them
}