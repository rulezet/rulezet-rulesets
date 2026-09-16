rule TTP_XOR_WriteProcessMemory_51a1 {
  strings:
    $key_51a1 = { 06 d3 [2] 34 f1 [2] 32 c4 [2] 1c c4 [2] 23 d8 }

  condition:
    any of them
}