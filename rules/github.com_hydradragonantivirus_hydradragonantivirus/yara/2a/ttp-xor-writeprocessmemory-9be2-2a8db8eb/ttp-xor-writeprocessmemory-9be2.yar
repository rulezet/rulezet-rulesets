rule TTP_XOR_WriteProcessMemory_9be2 {
  strings:
    $key_9be2 = { cc 90 [2] fe b2 [2] f8 87 [2] d6 87 [2] e9 9b }

  condition:
    any of them
}