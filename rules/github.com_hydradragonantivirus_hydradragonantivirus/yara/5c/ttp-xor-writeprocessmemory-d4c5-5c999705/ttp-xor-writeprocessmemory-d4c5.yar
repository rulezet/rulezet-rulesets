rule TTP_XOR_WriteProcessMemory_d4c5 {
  strings:
    $key_d4c5 = { 83 b7 [2] b1 95 [2] b7 a0 [2] 99 a0 [2] a6 bc }

  condition:
    any of them
}