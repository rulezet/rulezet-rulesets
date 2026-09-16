rule TTP_XOR_WriteProcessMemory_b527 {
  strings:
    $key_b527 = { e2 55 [2] d0 77 [2] d6 42 [2] f8 42 [2] c7 5e }

  condition:
    any of them
}