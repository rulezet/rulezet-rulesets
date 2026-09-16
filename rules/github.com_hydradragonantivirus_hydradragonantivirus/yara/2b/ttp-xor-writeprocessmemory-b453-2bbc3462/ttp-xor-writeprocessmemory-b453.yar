rule TTP_XOR_WriteProcessMemory_b453 {
  strings:
    $key_b453 = { e3 21 [2] d1 03 [2] d7 36 [2] f9 36 [2] c6 2a }

  condition:
    any of them
}