rule TTP_XOR_WriteProcessMemory_9b96 {
  strings:
    $key_9b96 = { cc e4 [2] fe c6 [2] f8 f3 [2] d6 f3 [2] e9 ef }

  condition:
    any of them
}