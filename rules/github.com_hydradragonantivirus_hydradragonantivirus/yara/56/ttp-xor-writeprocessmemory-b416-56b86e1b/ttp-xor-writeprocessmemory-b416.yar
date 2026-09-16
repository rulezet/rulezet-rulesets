rule TTP_XOR_WriteProcessMemory_b416 {
  strings:
    $key_b416 = { e3 64 [2] d1 46 [2] d7 73 [2] f9 73 [2] c6 6f }

  condition:
    any of them
}