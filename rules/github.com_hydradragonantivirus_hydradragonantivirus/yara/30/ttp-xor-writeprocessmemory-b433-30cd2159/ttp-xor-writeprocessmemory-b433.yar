rule TTP_XOR_WriteProcessMemory_b433 {
  strings:
    $key_b433 = { e3 41 [2] d1 63 [2] d7 56 [2] f9 56 [2] c6 4a }

  condition:
    any of them
}