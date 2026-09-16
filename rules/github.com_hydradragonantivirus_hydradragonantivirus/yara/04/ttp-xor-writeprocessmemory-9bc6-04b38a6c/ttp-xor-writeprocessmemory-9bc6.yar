rule TTP_XOR_WriteProcessMemory_9bc6 {
  strings:
    $key_9bc6 = { cc b4 [2] fe 96 [2] f8 a3 [2] d6 a3 [2] e9 bf }

  condition:
    any of them
}