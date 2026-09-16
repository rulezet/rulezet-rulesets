rule TTP_XOR_WriteProcessMemory_25a1 {
  strings:
    $key_25a1 = { 72 d3 [2] 40 f1 [2] 46 c4 [2] 68 c4 [2] 57 d8 }

  condition:
    any of them
}