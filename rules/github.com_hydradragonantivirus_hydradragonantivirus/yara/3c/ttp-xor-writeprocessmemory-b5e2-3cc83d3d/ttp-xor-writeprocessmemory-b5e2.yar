rule TTP_XOR_WriteProcessMemory_b5e2 {
  strings:
    $key_b5e2 = { e2 90 [2] d0 b2 [2] d6 87 [2] f8 87 [2] c7 9b }

  condition:
    any of them
}