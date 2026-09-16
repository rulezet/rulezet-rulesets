rule TTP_XOR_WriteProcessMemory_c4e2 {
  strings:
    $key_c4e2 = { 93 90 [2] a1 b2 [2] a7 87 [2] 89 87 [2] b6 9b }

  condition:
    any of them
}