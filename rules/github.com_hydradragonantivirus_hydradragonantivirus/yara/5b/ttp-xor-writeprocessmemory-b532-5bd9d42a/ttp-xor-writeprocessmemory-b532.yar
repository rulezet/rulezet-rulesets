rule TTP_XOR_WriteProcessMemory_b532 {
  strings:
    $key_b532 = { e2 40 [2] d0 62 [2] d6 57 [2] f8 57 [2] c7 4b }

  condition:
    any of them
}