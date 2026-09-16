rule TTP_XOR_WriteProcessMemory_b477 {
  strings:
    $key_b477 = { e3 05 [2] d1 27 [2] d7 12 [2] f9 12 [2] c6 0e }

  condition:
    any of them
}