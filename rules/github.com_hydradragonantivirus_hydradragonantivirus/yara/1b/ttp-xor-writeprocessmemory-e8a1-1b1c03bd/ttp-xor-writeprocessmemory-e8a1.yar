rule TTP_XOR_WriteProcessMemory_e8a1 {
  strings:
    $key_e8a1 = { bf d3 [2] 8d f1 [2] 8b c4 [2] a5 c4 [2] 9a d8 }

  condition:
    any of them
}