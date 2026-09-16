rule TTP_XOR_WriteProcessMemory_d2e1 {
  strings:
    $key_d2e1 = { 85 93 [2] b7 b1 [2] b1 84 [2] 9f 84 [2] a0 98 }

  condition:
    any of them
}