rule TTP_XOR_WriteProcessMemory_c7a0 {
  strings:
    $key_c7a0 = { 90 d2 [2] a2 f0 [2] a4 c5 [2] 8a c5 [2] b5 d9 }

  condition:
    any of them
}