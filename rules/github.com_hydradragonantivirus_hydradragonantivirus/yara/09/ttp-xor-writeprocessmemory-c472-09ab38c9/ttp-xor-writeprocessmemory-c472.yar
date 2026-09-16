rule TTP_XOR_WriteProcessMemory_c472 {
  strings:
    $key_c472 = { 93 00 [2] a1 22 [2] a7 17 [2] 89 17 [2] b6 0b }

  condition:
    any of them
}