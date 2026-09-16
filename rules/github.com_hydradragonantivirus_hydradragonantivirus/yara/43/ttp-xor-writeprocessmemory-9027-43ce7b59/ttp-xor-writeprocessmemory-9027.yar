rule TTP_XOR_WriteProcessMemory_9027 {
  strings:
    $key_9027 = { c7 55 [2] f5 77 [2] f3 42 [2] dd 42 [2] e2 5e }

  condition:
    any of them
}