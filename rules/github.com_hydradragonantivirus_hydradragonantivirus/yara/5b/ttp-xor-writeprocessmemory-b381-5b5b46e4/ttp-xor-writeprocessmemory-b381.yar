rule TTP_XOR_WriteProcessMemory_b381 {
  strings:
    $key_b381 = { e4 f3 [2] d6 d1 [2] d0 e4 [2] fe e4 [2] c1 f8 }

  condition:
    any of them
}