rule TTP_XOR_WriteProcessMemory_d6c5 {
  strings:
    $key_d6c5 = { 81 b7 [2] b3 95 [2] b5 a0 [2] 9b a0 [2] a4 bc }

  condition:
    any of them
}