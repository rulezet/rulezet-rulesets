rule TTP_XOR_WriteProcessMemory_9032 {
  strings:
    $key_9032 = { c7 40 [2] f5 62 [2] f3 57 [2] dd 57 [2] e2 4b }

  condition:
    any of them
}