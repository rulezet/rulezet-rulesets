rule TTP_XOR_WriteProcessMemory_9041 {
  strings:
    $key_9041 = { c7 33 [2] f5 11 [2] f3 24 [2] dd 24 [2] e2 38 }

  condition:
    any of them
}