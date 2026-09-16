rule TTP_XOR_WriteProcessMemory_b435 {
  strings:
    $key_b435 = { e3 47 [2] d1 65 [2] d7 50 [2] f9 50 [2] c6 4c }

  condition:
    any of them
}