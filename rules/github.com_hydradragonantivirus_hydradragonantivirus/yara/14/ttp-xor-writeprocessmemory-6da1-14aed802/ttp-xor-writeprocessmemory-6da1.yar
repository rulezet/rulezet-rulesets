rule TTP_XOR_WriteProcessMemory_6da1 {
  strings:
    $key_6da1 = { 3a d3 [2] 08 f1 [2] 0e c4 [2] 20 c4 [2] 1f d8 }

  condition:
    any of them
}