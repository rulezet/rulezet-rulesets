rule TTP_XOR_WriteProcessMemory_9070 {
  strings:
    $key_9070 = { c7 02 [2] f5 20 [2] f3 15 [2] dd 15 [2] e2 09 }

  condition:
    any of them
}