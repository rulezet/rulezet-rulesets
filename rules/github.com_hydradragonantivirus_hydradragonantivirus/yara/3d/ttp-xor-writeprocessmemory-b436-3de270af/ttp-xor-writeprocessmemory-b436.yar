rule TTP_XOR_WriteProcessMemory_b436 {
  strings:
    $key_b436 = { e3 44 [2] d1 66 [2] d7 53 [2] f9 53 [2] c6 4f }

  condition:
    any of them
}