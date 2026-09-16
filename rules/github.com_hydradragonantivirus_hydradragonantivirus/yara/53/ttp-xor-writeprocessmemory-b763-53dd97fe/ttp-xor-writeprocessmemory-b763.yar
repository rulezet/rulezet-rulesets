rule TTP_XOR_WriteProcessMemory_b763 {
  strings:
    $key_b763 = { e0 11 [2] d2 33 [2] d4 06 [2] fa 06 [2] c5 1a }

  condition:
    any of them
}