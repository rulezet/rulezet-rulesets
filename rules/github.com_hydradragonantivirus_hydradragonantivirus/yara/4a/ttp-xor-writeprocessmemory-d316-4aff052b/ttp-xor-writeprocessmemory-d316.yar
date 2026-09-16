rule TTP_XOR_WriteProcessMemory_d316 {
  strings:
    $key_d316 = { 84 64 [2] b6 46 [2] b0 73 [2] 9e 73 [2] a1 6f }

  condition:
    any of them
}