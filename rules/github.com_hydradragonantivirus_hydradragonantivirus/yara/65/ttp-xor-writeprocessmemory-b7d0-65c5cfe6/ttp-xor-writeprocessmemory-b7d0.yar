rule TTP_XOR_WriteProcessMemory_b7d0 {
  strings:
    $key_b7d0 = { e0 a2 [2] d2 80 [2] d4 b5 [2] fa b5 [2] c5 a9 }

  condition:
    any of them
}