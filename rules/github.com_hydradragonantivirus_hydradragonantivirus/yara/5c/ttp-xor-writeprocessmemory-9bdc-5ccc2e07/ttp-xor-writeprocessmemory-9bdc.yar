rule TTP_XOR_WriteProcessMemory_9bdc {
  strings:
    $key_9bdc = { cc ae [2] fe 8c [2] f8 b9 [2] d6 b9 [2] e9 a5 }

  condition:
    any of them
}