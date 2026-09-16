rule TTP_XOR_WriteProcessMemory_a6b4 {
  strings:
    $key_a6b4 = { f1 c6 [2] c3 e4 [2] c5 d1 [2] eb d1 [2] d4 cd }

  condition:
    any of them
}