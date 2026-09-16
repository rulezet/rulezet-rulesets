rule TTP_XOR_WriteProcessMemory_d576 {
  strings:
    $key_d576 = { 82 04 [2] b0 26 [2] b6 13 [2] 98 13 [2] a7 0f }

  condition:
    any of them
}