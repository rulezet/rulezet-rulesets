rule TTP_XOR_WriteProcessMemory_b490 {
  strings:
    $key_b490 = { e3 e2 [2] d1 c0 [2] d7 f5 [2] f9 f5 [2] c6 e9 }

  condition:
    any of them
}