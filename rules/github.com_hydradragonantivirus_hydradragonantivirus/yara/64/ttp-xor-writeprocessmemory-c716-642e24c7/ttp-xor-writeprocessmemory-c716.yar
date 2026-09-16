rule TTP_XOR_WriteProcessMemory_c716 {
  strings:
    $key_c716 = { 90 64 [2] a2 46 [2] a4 73 [2] 8a 73 [2] b5 6f }

  condition:
    any of them
}