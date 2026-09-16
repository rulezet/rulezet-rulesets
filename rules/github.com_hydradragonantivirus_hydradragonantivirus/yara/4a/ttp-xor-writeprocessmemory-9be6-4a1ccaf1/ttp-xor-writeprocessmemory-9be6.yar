rule TTP_XOR_WriteProcessMemory_9be6 {
  strings:
    $key_9be6 = { cc 94 [2] fe b6 [2] f8 83 [2] d6 83 [2] e9 9f }

  condition:
    any of them
}