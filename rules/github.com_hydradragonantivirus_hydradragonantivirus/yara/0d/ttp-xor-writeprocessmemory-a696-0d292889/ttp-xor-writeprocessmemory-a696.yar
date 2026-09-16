rule TTP_XOR_WriteProcessMemory_a696 {
  strings:
    $key_a696 = { f1 e4 [2] c3 c6 [2] c5 f3 [2] eb f3 [2] d4 ef }

  condition:
    any of them
}