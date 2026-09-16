rule TTP_XOR_WriteProcessMemory_9022 {
  strings:
    $key_9022 = { c7 50 [2] f5 72 [2] f3 47 [2] dd 47 [2] e2 5b }

  condition:
    any of them
}