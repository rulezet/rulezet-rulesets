rule TTP_XOR_WriteProcessMemory_b463 {
  strings:
    $key_b463 = { e3 11 [2] d1 33 [2] d7 06 [2] f9 06 [2] c6 1a }

  condition:
    any of them
}