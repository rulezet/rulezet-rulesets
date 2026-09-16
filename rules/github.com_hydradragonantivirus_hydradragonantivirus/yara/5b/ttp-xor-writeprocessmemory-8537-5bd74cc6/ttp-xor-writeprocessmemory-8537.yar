rule TTP_XOR_WriteProcessMemory_8537 {
  strings:
    $key_8537 = { d2 45 [2] e0 67 [2] e6 52 [2] c8 52 [2] f7 4e }

  condition:
    any of them
}