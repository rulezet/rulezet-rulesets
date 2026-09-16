rule TTP_XOR_WriteProcessMemory_d572 {
  strings:
    $key_d572 = { 82 00 [2] b0 22 [2] b6 17 [2] 98 17 [2] a7 0b }

  condition:
    any of them
}