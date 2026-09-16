rule TTP_XOR_WriteProcessMemory_b549 {
  strings:
    $key_b549 = { e2 3b [2] d0 19 [2] d6 2c [2] f8 2c [2] c7 30 }

  condition:
    any of them
}