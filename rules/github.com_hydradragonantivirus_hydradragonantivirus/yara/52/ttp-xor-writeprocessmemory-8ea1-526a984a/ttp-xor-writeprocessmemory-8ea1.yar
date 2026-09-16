rule TTP_XOR_WriteProcessMemory_8ea1 {
  strings:
    $key_8ea1 = { d9 d3 [2] eb f1 [2] ed c4 [2] c3 c4 [2] fc d8 }

  condition:
    any of them
}