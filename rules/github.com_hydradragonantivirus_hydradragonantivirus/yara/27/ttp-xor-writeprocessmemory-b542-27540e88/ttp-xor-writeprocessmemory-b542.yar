rule TTP_XOR_WriteProcessMemory_b542 {
  strings:
    $key_b542 = { e2 30 [2] d0 12 [2] d6 27 [2] f8 27 [2] c7 3b }

  condition:
    any of them
}