rule TTP_XOR_WriteProcessMemory_c4d2 {
  strings:
    $key_c4d2 = { 93 a0 [2] a1 82 [2] a7 b7 [2] 89 b7 [2] b6 ab }

  condition:
    any of them
}