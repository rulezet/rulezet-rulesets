rule TTP_XOR_WriteProcessMemory_26a1 {
  strings:
    $key_26a1 = { 71 d3 [2] 43 f1 [2] 45 c4 [2] 6b c4 [2] 54 d8 }

  condition:
    any of them
}