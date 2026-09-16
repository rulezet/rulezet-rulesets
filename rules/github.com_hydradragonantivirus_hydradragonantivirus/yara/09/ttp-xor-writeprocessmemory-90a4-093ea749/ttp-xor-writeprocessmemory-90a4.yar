rule TTP_XOR_WriteProcessMemory_90a4 {
  strings:
    $key_90a4 = { c7 d6 [2] f5 f4 [2] f3 c1 [2] dd c1 [2] e2 dd }

  condition:
    any of them
}