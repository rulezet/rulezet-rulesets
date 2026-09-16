rule TTP_XOR_WriteProcessMemory_c5e6 {
  strings:
    $key_c5e6 = { 92 94 [2] a0 b6 [2] a6 83 [2] 88 83 [2] b7 9f }

  condition:
    any of them
}