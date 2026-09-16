rule TTP_XOR_WriteProcessMemory_9018 {
  strings:
    $key_9018 = { c7 6a [2] f5 48 [2] f3 7d [2] dd 7d [2] e2 61 }

  condition:
    any of them
}