rule TTP_XOR_WriteProcessMemory_9339 {
  strings:
    $key_9339 = { c4 4b [2] f6 69 [2] f0 5c [2] de 5c [2] e1 40 }

  condition:
    any of them
}