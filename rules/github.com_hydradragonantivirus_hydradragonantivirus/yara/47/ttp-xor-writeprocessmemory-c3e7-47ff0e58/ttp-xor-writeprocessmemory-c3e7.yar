rule TTP_XOR_WriteProcessMemory_c3e7 {
  strings:
    $key_c3e7 = { 94 95 [2] a6 b7 [2] a0 82 [2] 8e 82 [2] b1 9e }

  condition:
    any of them
}