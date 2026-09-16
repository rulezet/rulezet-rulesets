rule TTP_XOR_WriteProcessMemory_9060 {
  strings:
    $key_9060 = { c7 12 [2] f5 30 [2] f3 05 [2] dd 05 [2] e2 19 }

  condition:
    any of them
}