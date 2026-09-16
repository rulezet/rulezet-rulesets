rule TTP_XOR_WriteProcessMemory_b572 {
  strings:
    $key_b572 = { e2 00 [2] d0 22 [2] d6 17 [2] f8 17 [2] c7 0b }

  condition:
    any of them
}