rule TTP_XOR_WriteProcessMemory_8562 {
  strings:
    $key_8562 = { d2 10 [2] e0 32 [2] e6 07 [2] c8 07 [2] f7 1b }

  condition:
    any of them
}