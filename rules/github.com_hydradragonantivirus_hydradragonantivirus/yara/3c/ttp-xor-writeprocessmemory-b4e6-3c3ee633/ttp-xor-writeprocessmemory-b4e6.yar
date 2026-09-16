rule TTP_XOR_WriteProcessMemory_b4e6 {
  strings:
    $key_b4e6 = { e3 94 [2] d1 b6 [2] d7 83 [2] f9 83 [2] c6 9f }

  condition:
    any of them
}