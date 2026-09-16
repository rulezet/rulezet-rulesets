rule TTP_XOR_WriteProcessMemory_c5e1 {
  strings:
    $key_c5e1 = { 92 93 [2] a0 b1 [2] a6 84 [2] 88 84 [2] b7 98 }

  condition:
    any of them
}