rule TTP_XOR_WriteProcessMemory_99d5 {
  strings:
    $key_99d5 = { ce a7 [2] fc 85 [2] fa b0 [2] d4 b0 [2] eb ac }

  condition:
    any of them
}