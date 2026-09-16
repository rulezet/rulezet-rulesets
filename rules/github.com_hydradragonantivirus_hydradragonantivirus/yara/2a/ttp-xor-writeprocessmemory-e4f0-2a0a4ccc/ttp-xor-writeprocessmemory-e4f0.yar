rule TTP_XOR_WriteProcessMemory_e4f0 {
  strings:
    $key_e4f0 = { b3 82 [2] 81 a0 [2] 87 95 [2] a9 95 [2] 96 89 }

  condition:
    any of them
}