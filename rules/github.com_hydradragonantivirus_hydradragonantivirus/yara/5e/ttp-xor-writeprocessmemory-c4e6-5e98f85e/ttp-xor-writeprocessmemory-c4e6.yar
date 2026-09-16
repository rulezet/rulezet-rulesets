rule TTP_XOR_WriteProcessMemory_c4e6 {
  strings:
    $key_c4e6 = { 93 94 [2] a1 b6 [2] a7 83 [2] 89 83 [2] b6 9f }

  condition:
    any of them
}