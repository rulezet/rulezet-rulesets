rule TTP_XOR_WriteProcessMemory_d4e2 {
  strings:
    $key_d4e2 = { 83 90 [2] b1 b2 [2] b7 87 [2] 99 87 [2] a6 9b }

  condition:
    any of them
}