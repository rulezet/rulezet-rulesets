rule TTP_XOR_WriteProcessMemory_a0b1 {
  strings:
    $key_a0b1 = { f7 c3 [2] c5 e1 [2] c3 d4 [2] ed d4 [2] d2 c8 }

  condition:
    any of them
}