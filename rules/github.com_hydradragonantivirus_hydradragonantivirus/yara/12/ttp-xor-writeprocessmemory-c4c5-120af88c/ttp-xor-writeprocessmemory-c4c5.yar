rule TTP_XOR_WriteProcessMemory_c4c5 {
  strings:
    $key_c4c5 = { 93 b7 [2] a1 95 [2] a7 a0 [2] 89 a0 [2] b6 bc }

  condition:
    any of them
}