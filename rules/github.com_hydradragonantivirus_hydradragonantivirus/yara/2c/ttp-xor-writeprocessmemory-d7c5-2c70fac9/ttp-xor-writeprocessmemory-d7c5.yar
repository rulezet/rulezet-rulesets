rule TTP_XOR_WriteProcessMemory_d7c5 {
  strings:
    $key_d7c5 = { 80 b7 [2] b2 95 [2] b4 a0 [2] 9a a0 [2] a5 bc }

  condition:
    any of them
}