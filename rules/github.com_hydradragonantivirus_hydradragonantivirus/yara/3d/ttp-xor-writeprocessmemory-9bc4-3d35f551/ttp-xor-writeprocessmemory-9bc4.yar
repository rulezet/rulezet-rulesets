rule TTP_XOR_WriteProcessMemory_9bc4 {
  strings:
    $key_9bc4 = { cc b6 [2] fe 94 [2] f8 a1 [2] d6 a1 [2] e9 bd }

  condition:
    any of them
}