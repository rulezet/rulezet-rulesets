rule TTP_XOR_WriteProcessMemory_c516 {
  strings:
    $key_c516 = { 92 64 [2] a0 46 [2] a6 73 [2] 88 73 [2] b7 6f }

  condition:
    any of them
}