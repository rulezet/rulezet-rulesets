rule TTP_XOR_WriteProcessMemory_a5f0 {
  strings:
    $key_a5f0 = { f2 82 [2] c0 a0 [2] c6 95 [2] e8 95 [2] d7 89 }

  condition:
    any of them
}