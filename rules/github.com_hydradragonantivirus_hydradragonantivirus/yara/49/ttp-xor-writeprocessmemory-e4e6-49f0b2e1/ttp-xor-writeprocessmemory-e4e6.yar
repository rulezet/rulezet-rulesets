rule TTP_XOR_WriteProcessMemory_e4e6 {
  strings:
    $key_e4e6 = { b3 94 [2] 81 b6 [2] 87 83 [2] a9 83 [2] 96 9f }

  condition:
    any of them
}