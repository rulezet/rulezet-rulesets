rule TTP_XOR_WriteProcessMemory_b760 {
  strings:
    $key_b760 = { e0 12 [2] d2 30 [2] d4 05 [2] fa 05 [2] c5 19 }

  condition:
    any of them
}