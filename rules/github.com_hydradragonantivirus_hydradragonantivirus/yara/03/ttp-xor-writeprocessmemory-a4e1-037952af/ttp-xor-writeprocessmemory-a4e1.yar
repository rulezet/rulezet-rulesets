rule TTP_XOR_WriteProcessMemory_a4e1 {
  strings:
    $key_a4e1 = { f3 93 [2] c1 b1 [2] c7 84 [2] e9 84 [2] d6 98 }

  condition:
    any of them
}