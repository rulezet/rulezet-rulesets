rule TTP_XOR_WriteProcessMemory_b563 {
  strings:
    $key_b563 = { e2 11 [2] d0 33 [2] d6 06 [2] f8 06 [2] c7 1a }

  condition:
    any of them
}