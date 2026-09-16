rule TTP_XOR_WriteProcessMemory_c3e6 {
  strings:
    $key_c3e6 = { 94 94 [2] a6 b6 [2] a0 83 [2] 8e 83 [2] b1 9f }

  condition:
    any of them
}