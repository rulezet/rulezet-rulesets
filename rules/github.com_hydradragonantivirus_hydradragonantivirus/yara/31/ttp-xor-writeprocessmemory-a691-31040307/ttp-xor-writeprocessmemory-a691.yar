rule TTP_XOR_WriteProcessMemory_a691 {
  strings:
    $key_a691 = { f1 e3 [2] c3 c1 [2] c5 f4 [2] eb f4 [2] d4 e8 }

  condition:
    any of them
}