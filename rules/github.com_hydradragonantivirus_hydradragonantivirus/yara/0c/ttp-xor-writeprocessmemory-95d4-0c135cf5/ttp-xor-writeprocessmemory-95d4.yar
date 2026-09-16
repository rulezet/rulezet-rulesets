rule TTP_XOR_WriteProcessMemory_95d4 {
  strings:
    $key_95d4 = { c2 a6 [2] f0 84 [2] f6 b1 [2] d8 b1 [2] e7 ad }

  condition:
    any of them
}