rule TTP_XOR_WriteProcessMemory_9bfa {
  strings:
    $key_9bfa = { cc 88 [2] fe aa [2] f8 9f [2] d6 9f [2] e9 83 }

  condition:
    any of them
}