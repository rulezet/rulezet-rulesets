rule TTP_XOR_WriteProcessMemory_9b87 {
  strings:
    $key_9b87 = { cc f5 [2] fe d7 [2] f8 e2 [2] d6 e2 [2] e9 fe }

  condition:
    any of them
}