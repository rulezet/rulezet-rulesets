rule TTP_XOR_WriteProcessMemory_9bed {
  strings:
    $key_9bed = { cc 9f [2] fe bd [2] f8 88 [2] d6 88 [2] e9 94 }

  condition:
    any of them
}