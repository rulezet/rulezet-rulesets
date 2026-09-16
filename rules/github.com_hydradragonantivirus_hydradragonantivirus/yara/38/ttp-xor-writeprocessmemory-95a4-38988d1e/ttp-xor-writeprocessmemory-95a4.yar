rule TTP_XOR_WriteProcessMemory_95a4 {
  strings:
    $key_95a4 = { c2 d6 [2] f0 f4 [2] f6 c1 [2] d8 c1 [2] e7 dd }

  condition:
    any of them
}