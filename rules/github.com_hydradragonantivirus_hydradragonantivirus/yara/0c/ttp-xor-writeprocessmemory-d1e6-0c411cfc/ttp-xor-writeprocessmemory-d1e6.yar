rule TTP_XOR_WriteProcessMemory_d1e6 {
  strings:
    $key_d1e6 = { 86 94 [2] b4 b6 [2] b2 83 [2] 9c 83 [2] a3 9f }

  condition:
    any of them
}