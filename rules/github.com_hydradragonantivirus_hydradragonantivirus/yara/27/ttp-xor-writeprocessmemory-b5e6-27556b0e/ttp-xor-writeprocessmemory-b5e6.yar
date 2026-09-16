rule TTP_XOR_WriteProcessMemory_b5e6 {
  strings:
    $key_b5e6 = { e2 94 [2] d0 b6 [2] d6 83 [2] f8 83 [2] c7 9f }

  condition:
    any of them
}