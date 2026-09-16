rule TTP_XOR_WriteProcessMemory_9063 {
  strings:
    $key_9063 = { c7 11 [2] f5 33 [2] f3 06 [2] dd 06 [2] e2 1a }

  condition:
    any of them
}