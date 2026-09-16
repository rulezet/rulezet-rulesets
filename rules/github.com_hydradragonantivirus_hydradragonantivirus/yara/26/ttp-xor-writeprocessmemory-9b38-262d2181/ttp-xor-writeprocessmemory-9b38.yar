rule TTP_XOR_WriteProcessMemory_9b38 {
  strings:
    $key_9b38 = { cc 4a [2] fe 68 [2] f8 5d [2] d6 5d [2] e9 41 }

  condition:
    any of them
}