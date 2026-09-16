rule TTP_XOR_WriteProcessMemory_e4a1 {
  strings:
    $key_e4a1 = { b3 d3 [2] 81 f1 [2] 87 c4 [2] a9 c4 [2] 96 d8 }

  condition:
    any of them
}