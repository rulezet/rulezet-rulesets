rule TTP_XOR_WriteProcessMemory_41a1 {
  strings:
    $key_41a1 = { 16 d3 [2] 24 f1 [2] 22 c4 [2] 0c c4 [2] 33 d8 }

  condition:
    any of them
}