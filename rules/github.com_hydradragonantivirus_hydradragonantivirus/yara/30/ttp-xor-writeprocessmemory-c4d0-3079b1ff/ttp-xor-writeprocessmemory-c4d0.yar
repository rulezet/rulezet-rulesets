rule TTP_XOR_WriteProcessMemory_c4d0 {
  strings:
    $key_c4d0 = { 93 a2 [2] a1 80 [2] a7 b5 [2] 89 b5 [2] b6 a9 }

  condition:
    any of them
}