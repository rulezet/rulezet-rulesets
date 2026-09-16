rule TTP_XOR_WriteProcessMemory_9b09 {
  strings:
    $key_9b09 = { cc 7b [2] fe 59 [2] f8 6c [2] d6 6c [2] e9 70 }

  condition:
    any of them
}