rule TTP_XOR_WriteProcessMemory_c5e2 {
  strings:
    $key_c5e2 = { 92 90 [2] a0 b2 [2] a6 87 [2] 88 87 [2] b7 9b }

  condition:
    any of them
}