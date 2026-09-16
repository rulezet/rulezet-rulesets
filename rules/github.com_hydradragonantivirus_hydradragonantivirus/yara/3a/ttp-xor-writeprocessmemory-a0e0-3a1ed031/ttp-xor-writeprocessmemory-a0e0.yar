rule TTP_XOR_WriteProcessMemory_a0e0 {
  strings:
    $key_a0e0 = { f7 92 [2] c5 b0 [2] c3 85 [2] ed 85 [2] d2 99 }

  condition:
    any of them
}