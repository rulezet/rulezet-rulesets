rule TTP_XOR_WriteProcessMemory_a427 {
  strings:
    $key_a427 = { f3 55 [2] c1 77 [2] c7 42 [2] e9 42 [2] d6 5e }

  condition:
    any of them
}