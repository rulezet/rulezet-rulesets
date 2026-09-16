rule TTP_XOR_WriteProcessMemory_9006 {
  strings:
    $key_9006 = { c7 74 [2] f5 56 [2] f3 63 [2] dd 63 [2] e2 7f }

  condition:
    any of them
}