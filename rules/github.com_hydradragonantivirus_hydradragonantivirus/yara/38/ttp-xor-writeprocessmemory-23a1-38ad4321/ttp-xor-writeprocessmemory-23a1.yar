rule TTP_XOR_WriteProcessMemory_23a1 {
  strings:
    $key_23a1 = { 74 d3 [2] 46 f1 [2] 40 c4 [2] 6e c4 [2] 51 d8 }

  condition:
    any of them
}