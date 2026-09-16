rule TTP_XOR_WriteProcessMemory_b390 {
  strings:
    $key_b390 = { e4 e2 [2] d6 c0 [2] d0 f5 [2] fe f5 [2] c1 e9 }

  condition:
    any of them
}