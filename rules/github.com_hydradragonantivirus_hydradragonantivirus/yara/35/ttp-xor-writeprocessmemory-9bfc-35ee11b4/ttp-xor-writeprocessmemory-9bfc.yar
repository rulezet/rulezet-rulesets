rule TTP_XOR_WriteProcessMemory_9bfc {
  strings:
    $key_9bfc = { cc 8e [2] fe ac [2] f8 99 [2] d6 99 [2] e9 85 }

  condition:
    any of them
}