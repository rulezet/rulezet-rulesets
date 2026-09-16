rule TTP_XOR_WriteProcessMemory_9bea {
  strings:
    $key_9bea = { cc 98 [2] fe ba [2] f8 8f [2] d6 8f [2] e9 93 }

  condition:
    any of them
}