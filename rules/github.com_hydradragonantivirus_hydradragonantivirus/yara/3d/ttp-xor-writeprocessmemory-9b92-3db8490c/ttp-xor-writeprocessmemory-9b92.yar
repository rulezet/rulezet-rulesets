rule TTP_XOR_WriteProcessMemory_9b92 {
  strings:
    $key_9b92 = { cc e0 [2] fe c2 [2] f8 f7 [2] d6 f7 [2] e9 eb }

  condition:
    any of them
}