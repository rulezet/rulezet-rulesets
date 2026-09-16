rule TTP_XOR_WriteProcessMemory_b751 {
  strings:
    $key_b751 = { e0 23 [2] d2 01 [2] d4 34 [2] fa 34 [2] c5 28 }

  condition:
    any of them
}