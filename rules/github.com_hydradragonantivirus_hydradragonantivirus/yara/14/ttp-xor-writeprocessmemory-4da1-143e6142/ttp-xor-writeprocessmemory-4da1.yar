rule TTP_XOR_WriteProcessMemory_4da1 {
  strings:
    $key_4da1 = { 1a d3 [2] 28 f1 [2] 2e c4 [2] 00 c4 [2] 3f d8 }

  condition:
    any of them
}