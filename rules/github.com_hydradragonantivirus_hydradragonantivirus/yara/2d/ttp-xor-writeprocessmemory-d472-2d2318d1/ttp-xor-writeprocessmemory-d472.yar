rule TTP_XOR_WriteProcessMemory_d472 {
  strings:
    $key_d472 = { 83 00 [2] b1 22 [2] b7 17 [2] 99 17 [2] a6 0b }

  condition:
    any of them
}