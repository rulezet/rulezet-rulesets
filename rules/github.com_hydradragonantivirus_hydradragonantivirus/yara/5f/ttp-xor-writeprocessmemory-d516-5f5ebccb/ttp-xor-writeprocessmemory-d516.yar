rule TTP_XOR_WriteProcessMemory_d516 {
  strings:
    $key_d516 = { 82 64 [2] b0 46 [2] b6 73 [2] 98 73 [2] a7 6f }

  condition:
    any of them
}