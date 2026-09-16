rule TTP_XOR_WriteProcessMemory_9555 {
  strings:
    $key_9555 = { c2 27 [2] f0 05 [2] f6 30 [2] d8 30 [2] e7 2c }

  condition:
    any of them
}