rule TTP_XOR_WriteProcessMemory_d0d4 {
  strings:
    $key_d0d4 = { 87 a6 [2] b5 84 [2] b3 b1 [2] 9d b1 [2] a2 ad }

  condition:
    any of them
}