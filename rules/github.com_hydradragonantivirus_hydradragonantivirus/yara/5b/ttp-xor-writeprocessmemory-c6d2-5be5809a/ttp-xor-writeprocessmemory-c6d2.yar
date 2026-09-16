rule TTP_XOR_WriteProcessMemory_c6d2 {
  strings:
    $key_c6d2 = { 91 a0 [2] a3 82 [2] a5 b7 [2] 8b b7 [2] b4 ab }

  condition:
    any of them
}