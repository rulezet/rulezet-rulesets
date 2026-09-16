rule TTP_XOR_WriteProcessMemory_a0b0 {
  strings:
    $key_a0b0 = { f7 c2 [2] c5 e0 [2] c3 d5 [2] ed d5 [2] d2 c9 }

  condition:
    any of them
}