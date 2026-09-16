rule TTP_XOR_WriteProcessMemory_99d2 {
  strings:
    $key_99d2 = { ce a0 [2] fc 82 [2] fa b7 [2] d4 b7 [2] eb ab }

  condition:
    any of them
}