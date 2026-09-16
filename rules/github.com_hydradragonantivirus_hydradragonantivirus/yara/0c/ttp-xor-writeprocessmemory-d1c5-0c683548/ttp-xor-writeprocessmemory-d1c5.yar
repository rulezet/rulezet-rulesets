rule TTP_XOR_WriteProcessMemory_d1c5 {
  strings:
    $key_d1c5 = { 86 b7 [2] b4 95 [2] b2 a0 [2] 9c a0 [2] a3 bc }

  condition:
    any of them
}