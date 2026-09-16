rule TTP_XOR_WriteProcessMemory_a680 {
  strings:
    $key_a680 = { f1 f2 [2] c3 d0 [2] c5 e5 [2] eb e5 [2] d4 f9 }

  condition:
    any of them
}