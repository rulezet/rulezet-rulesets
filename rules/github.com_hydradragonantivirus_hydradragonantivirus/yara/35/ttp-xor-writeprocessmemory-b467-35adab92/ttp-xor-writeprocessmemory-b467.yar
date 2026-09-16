rule TTP_XOR_WriteProcessMemory_b467 {
  strings:
    $key_b467 = { e3 15 [2] d1 37 [2] d7 02 [2] f9 02 [2] c6 1e }

  condition:
    any of them
}