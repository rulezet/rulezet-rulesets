rule TTP_XOR_WriteProcessMemory_9066 {
  strings:
    $key_9066 = { c7 14 [2] f5 36 [2] f3 03 [2] dd 03 [2] e2 1f }

  condition:
    any of them
}