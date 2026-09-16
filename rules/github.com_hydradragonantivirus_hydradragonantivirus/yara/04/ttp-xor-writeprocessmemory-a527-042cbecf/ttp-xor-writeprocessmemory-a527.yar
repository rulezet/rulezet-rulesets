rule TTP_XOR_WriteProcessMemory_a527 {
  strings:
    $key_a527 = { f2 55 [2] c0 77 [2] c6 42 [2] e8 42 [2] d7 5e }

  condition:
    any of them
}