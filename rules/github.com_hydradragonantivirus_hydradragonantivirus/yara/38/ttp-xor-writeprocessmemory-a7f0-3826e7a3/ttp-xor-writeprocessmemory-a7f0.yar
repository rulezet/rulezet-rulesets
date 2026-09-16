rule TTP_XOR_WriteProcessMemory_a7f0 {
  strings:
    $key_a7f0 = { f0 82 [2] c2 a0 [2] c4 95 [2] ea 95 [2] d5 89 }

  condition:
    any of them
}