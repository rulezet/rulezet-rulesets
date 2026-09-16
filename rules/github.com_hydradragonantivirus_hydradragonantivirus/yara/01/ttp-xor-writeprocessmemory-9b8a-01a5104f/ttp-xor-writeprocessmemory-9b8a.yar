rule TTP_XOR_WriteProcessMemory_9b8a {
  strings:
    $key_9b8a = { cc f8 [2] fe da [2] f8 ef [2] d6 ef [2] e9 f3 }

  condition:
    any of them
}