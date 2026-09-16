rule TTP_XOR_WriteProcessMemory_9069 {
  strings:
    $key_9069 = { c7 1b [2] f5 39 [2] f3 0c [2] dd 0c [2] e2 10 }

  condition:
    any of them
}