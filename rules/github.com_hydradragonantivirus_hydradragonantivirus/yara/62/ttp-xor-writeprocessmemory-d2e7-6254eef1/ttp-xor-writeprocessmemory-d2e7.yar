rule TTP_XOR_WriteProcessMemory_d2e7 {
  strings:
    $key_d2e7 = { 85 95 [2] b7 b7 [2] b1 82 [2] 9f 82 [2] a0 9e }

  condition:
    any of them
}