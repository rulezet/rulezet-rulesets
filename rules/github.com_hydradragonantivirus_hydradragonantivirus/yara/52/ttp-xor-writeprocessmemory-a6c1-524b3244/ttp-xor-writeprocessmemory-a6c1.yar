rule TTP_XOR_WriteProcessMemory_a6c1 {
  strings:
    $key_a6c1 = { f1 b3 [2] c3 91 [2] c5 a4 [2] eb a4 [2] d4 b8 }

  condition:
    any of them
}