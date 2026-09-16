rule TTP_XOR_WriteProcessMemory_99d1 {
  strings:
    $key_99d1 = { ce a3 [2] fc 81 [2] fa b4 [2] d4 b4 [2] eb a8 }

  condition:
    any of them
}