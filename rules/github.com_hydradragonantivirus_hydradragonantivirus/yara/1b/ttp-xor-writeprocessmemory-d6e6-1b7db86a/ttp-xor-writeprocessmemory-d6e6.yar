rule TTP_XOR_WriteProcessMemory_d6e6 {
  strings:
    $key_d6e6 = { 81 94 [2] b3 b6 [2] b5 83 [2] 9b 83 [2] a4 9f }

  condition:
    any of them
}