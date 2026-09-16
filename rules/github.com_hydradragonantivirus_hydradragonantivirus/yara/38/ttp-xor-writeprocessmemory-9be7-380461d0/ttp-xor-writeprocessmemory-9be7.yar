rule TTP_XOR_WriteProcessMemory_9be7 {
  strings:
    $key_9be7 = { cc 95 [2] fe b7 [2] f8 82 [2] d6 82 [2] e9 9e }

  condition:
    any of them
}