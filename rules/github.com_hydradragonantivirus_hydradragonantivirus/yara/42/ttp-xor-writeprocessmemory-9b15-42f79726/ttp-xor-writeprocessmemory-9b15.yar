rule TTP_XOR_WriteProcessMemory_9b15 {
  strings:
    $key_9b15 = { cc 67 [2] fe 45 [2] f8 70 [2] d6 70 [2] e9 6c }

  condition:
    any of them
}