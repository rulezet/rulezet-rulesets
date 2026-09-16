rule TTP_XOR_WriteProcessMemory_31a1 {
  strings:
    $key_31a1 = { 66 d3 [2] 54 f1 [2] 52 c4 [2] 7c c4 [2] 43 d8 }

  condition:
    any of them
}