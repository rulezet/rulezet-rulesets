rule TTP_XOR_WriteProcessMemory_b427 {
  strings:
    $key_b427 = { e3 55 [2] d1 77 [2] d7 42 [2] f9 42 [2] c6 5e }

  condition:
    any of them
}