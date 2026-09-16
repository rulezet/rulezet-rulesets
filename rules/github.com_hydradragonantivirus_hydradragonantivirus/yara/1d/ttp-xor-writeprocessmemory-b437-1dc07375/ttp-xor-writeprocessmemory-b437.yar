rule TTP_XOR_WriteProcessMemory_b437 {
  strings:
    $key_b437 = { e3 45 [2] d1 67 [2] d7 52 [2] f9 52 [2] c6 4e }

  condition:
    any of them
}