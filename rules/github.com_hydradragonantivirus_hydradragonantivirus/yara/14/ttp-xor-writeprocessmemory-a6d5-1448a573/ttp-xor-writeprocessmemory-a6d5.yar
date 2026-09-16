rule TTP_XOR_WriteProcessMemory_a6d5 {
  strings:
    $key_a6d5 = { f1 a7 [2] c3 85 [2] c5 b0 [2] eb b0 [2] d4 ac }

  condition:
    any of them
}