rule TTP_XOR_WriteProcessMemory_b546 {
  strings:
    $key_b546 = { e2 34 [2] d0 16 [2] d6 23 [2] f8 23 [2] c7 3f }

  condition:
    any of them
}