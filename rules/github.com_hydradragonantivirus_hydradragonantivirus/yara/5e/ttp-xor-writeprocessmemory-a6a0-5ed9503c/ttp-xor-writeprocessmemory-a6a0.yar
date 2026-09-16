rule TTP_XOR_WriteProcessMemory_a6a0 {
  strings:
    $key_a6a0 = { f1 d2 [2] c3 f0 [2] c5 c5 [2] eb c5 [2] d4 d9 }

  condition:
    any of them
}