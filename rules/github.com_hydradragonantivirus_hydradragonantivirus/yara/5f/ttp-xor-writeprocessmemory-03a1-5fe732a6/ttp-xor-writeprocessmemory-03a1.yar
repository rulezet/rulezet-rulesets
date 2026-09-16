rule TTP_XOR_WriteProcessMemory_03a1 {
  strings:
    $key_03a1 = { 54 d3 [2] 66 f1 [2] 60 c4 [2] 4e c4 [2] 71 d8 }

  condition:
    any of them
}