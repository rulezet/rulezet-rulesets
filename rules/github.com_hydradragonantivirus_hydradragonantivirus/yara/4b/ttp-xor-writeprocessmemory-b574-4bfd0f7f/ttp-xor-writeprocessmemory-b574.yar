rule TTP_XOR_WriteProcessMemory_b574 {
  strings:
    $key_b574 = { e2 06 [2] d0 24 [2] d6 11 [2] f8 11 [2] c7 0d }

  condition:
    any of them
}