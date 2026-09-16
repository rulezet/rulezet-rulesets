rule TTP_XOR_WriteProcessMemory_a590 {
  strings:
    $key_a590 = { f2 e2 [2] c0 c0 [2] c6 f5 [2] e8 f5 [2] d7 e9 }

  condition:
    any of them
}