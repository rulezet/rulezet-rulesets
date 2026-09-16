rule TTP_XOR_WriteProcessMemory_9009 {
  strings:
    $key_9009 = { c7 7b [2] f5 59 [2] f3 6c [2] dd 6c [2] e2 70 }

  condition:
    any of them
}