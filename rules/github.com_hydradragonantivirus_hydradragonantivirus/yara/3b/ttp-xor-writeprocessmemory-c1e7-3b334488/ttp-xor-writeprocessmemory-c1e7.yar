rule TTP_XOR_WriteProcessMemory_c1e7 {
  strings:
    $key_c1e7 = { 96 95 [2] a4 b7 [2] a2 82 [2] 8c 82 [2] b3 9e }

  condition:
    any of them
}