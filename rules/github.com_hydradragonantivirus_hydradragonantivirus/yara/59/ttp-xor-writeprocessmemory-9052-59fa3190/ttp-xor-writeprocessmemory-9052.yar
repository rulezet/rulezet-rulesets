rule TTP_XOR_WriteProcessMemory_9052 {
  strings:
    $key_9052 = { c7 20 [2] f5 02 [2] f3 37 [2] dd 37 [2] e2 2b }

  condition:
    any of them
}