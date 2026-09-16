rule TTP_XOR_WriteProcessMemory_c1c5 {
  strings:
    $key_c1c5 = { 96 b7 [2] a4 95 [2] a2 a0 [2] 8c a0 [2] b3 bc }

  condition:
    any of them
}