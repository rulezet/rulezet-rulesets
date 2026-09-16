rule TTP_XOR_WriteProcessMemory_b462 {
  strings:
    $key_b462 = { e3 10 [2] d1 32 [2] d7 07 [2] f9 07 [2] c6 1b }

  condition:
    any of them
}