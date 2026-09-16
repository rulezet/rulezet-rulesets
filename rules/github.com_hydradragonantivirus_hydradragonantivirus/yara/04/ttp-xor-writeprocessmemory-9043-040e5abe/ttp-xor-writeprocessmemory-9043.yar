rule TTP_XOR_WriteProcessMemory_9043 {
  strings:
    $key_9043 = { c7 31 [2] f5 13 [2] f3 26 [2] dd 26 [2] e2 3a }

  condition:
    any of them
}