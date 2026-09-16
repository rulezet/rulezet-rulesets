rule TTP_XOR_WriteProcessMemory_9bac {
  strings:
    $key_9bac = { cc de [2] fe fc [2] f8 c9 [2] d6 c9 [2] e9 d5 }

  condition:
    any of them
}