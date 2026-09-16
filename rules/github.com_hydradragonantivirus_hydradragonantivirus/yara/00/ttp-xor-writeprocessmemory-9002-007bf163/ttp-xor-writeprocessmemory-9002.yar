rule TTP_XOR_WriteProcessMemory_9002 {
  strings:
    $key_9002 = { c7 70 [2] f5 52 [2] f3 67 [2] dd 67 [2] e2 7b }

  condition:
    any of them
}