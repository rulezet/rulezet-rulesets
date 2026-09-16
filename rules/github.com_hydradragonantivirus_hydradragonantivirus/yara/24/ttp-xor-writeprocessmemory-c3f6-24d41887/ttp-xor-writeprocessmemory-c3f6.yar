rule TTP_XOR_WriteProcessMemory_c3f6 {
  strings:
    $key_c3f6 = { 94 84 [2] a6 a6 [2] a0 93 [2] 8e 93 [2] b1 8f }

  condition:
    any of them
}