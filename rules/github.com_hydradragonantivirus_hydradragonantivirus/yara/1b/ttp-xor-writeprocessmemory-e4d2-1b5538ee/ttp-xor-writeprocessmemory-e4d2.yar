rule TTP_XOR_WriteProcessMemory_e4d2 {
  strings:
    $key_e4d2 = { b3 a0 [2] 81 82 [2] 87 b7 [2] a9 b7 [2] 96 ab }

  condition:
    any of them
}