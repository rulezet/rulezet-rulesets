rule TTP_XOR_WriteProcessMemory_c316 {
  strings:
    $key_c316 = { 94 64 [2] a6 46 [2] a0 73 [2] 8e 73 [2] b1 6f }

  condition:
    any of them
}