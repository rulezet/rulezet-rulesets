rule TTP_XOR_WriteProcessMemory_b506 {
  strings:
    $key_b506 = { e2 74 [2] d0 56 [2] d6 63 [2] f8 63 [2] c7 7f }

  condition:
    any of them
}