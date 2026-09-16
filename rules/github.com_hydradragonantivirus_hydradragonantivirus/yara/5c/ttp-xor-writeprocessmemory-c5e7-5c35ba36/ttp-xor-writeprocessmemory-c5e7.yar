rule TTP_XOR_WriteProcessMemory_c5e7 {
  strings:
    $key_c5e7 = { 92 95 [2] a0 b7 [2] a6 82 [2] 88 82 [2] b7 9e }

  condition:
    any of them
}