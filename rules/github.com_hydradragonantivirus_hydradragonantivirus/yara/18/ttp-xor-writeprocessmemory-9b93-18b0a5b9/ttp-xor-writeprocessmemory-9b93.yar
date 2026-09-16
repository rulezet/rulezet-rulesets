rule TTP_XOR_WriteProcessMemory_9b93 {
  strings:
    $key_9b93 = { cc e1 [2] fe c3 [2] f8 f6 [2] d6 f6 [2] e9 ea }

  condition:
    any of them
}