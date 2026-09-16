rule TTP_XOR_WriteProcessMemory_9565 {
  strings:
    $key_9565 = { c2 17 [2] f0 35 [2] f6 00 [2] d8 00 [2] e7 1c }

  condition:
    any of them
}