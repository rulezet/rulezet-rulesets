rule TTP_XOR_WriteProcessMemory_c4c0 {
  strings:
    $key_c4c0 = { 93 b2 [2] a1 90 [2] a7 a5 [2] 89 a5 [2] b6 b9 }

  condition:
    any of them
}