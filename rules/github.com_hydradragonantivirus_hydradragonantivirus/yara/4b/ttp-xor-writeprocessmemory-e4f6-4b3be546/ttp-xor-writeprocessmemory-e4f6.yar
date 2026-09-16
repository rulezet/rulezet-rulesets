rule TTP_XOR_WriteProcessMemory_e4f6 {
  strings:
    $key_e4f6 = { b3 84 [2] 81 a6 [2] 87 93 [2] a9 93 [2] 96 8f }

  condition:
    any of them
}