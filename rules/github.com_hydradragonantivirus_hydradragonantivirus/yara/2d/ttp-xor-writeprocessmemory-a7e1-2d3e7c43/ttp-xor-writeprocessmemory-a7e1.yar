rule TTP_XOR_WriteProcessMemory_a7e1 {
  strings:
    $key_a7e1 = { f0 93 [2] c2 b1 [2] c4 84 [2] ea 84 [2] d5 98 }

  condition:
    any of them
}