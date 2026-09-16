rule TTP_XOR_WriteProcessMemory_9bda {
  strings:
    $key_9bda = { cc a8 [2] fe 8a [2] f8 bf [2] d6 bf [2] e9 a3 }

  condition:
    any of them
}