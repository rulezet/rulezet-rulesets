rule TTP_XOR_WriteProcessMemory_9020 {
  strings:
    $key_9020 = { c7 52 [2] f5 70 [2] f3 45 [2] dd 45 [2] e2 59 }

  condition:
    any of them
}