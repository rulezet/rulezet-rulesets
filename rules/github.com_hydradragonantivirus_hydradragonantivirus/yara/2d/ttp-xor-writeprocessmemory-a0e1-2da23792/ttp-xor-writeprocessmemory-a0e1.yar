rule TTP_XOR_WriteProcessMemory_a0e1 {
  strings:
    $key_a0e1 = { f7 93 [2] c5 b1 [2] c3 84 [2] ed 84 [2] d2 98 }

  condition:
    any of them
}