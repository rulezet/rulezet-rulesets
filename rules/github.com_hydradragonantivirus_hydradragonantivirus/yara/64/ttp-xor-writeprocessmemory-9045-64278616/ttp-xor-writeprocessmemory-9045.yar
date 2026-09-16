rule TTP_XOR_WriteProcessMemory_9045 {
  strings:
    $key_9045 = { c7 37 [2] f5 15 [2] f3 20 [2] dd 20 [2] e2 3c }

  condition:
    any of them
}