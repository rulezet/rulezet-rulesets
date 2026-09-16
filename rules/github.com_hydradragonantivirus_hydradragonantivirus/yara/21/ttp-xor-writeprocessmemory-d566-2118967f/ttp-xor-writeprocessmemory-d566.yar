rule TTP_XOR_WriteProcessMemory_d566 {
  strings:
    $key_d566 = { 82 14 [2] b0 36 [2] b6 03 [2] 98 03 [2] a7 1f }

  condition:
    any of them
}