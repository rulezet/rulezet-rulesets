rule TTP_XOR_WriteProcessMemory_b7f0 {
  strings:
    $key_b7f0 = { e0 82 [2] d2 a0 [2] d4 95 [2] fa 95 [2] c5 89 }

  condition:
    any of them
}