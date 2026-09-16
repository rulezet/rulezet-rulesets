rule TTP_XOR_WriteProcessMemory_9b01 {
  strings:
    $key_9b01 = { cc 73 [2] fe 51 [2] f8 64 [2] d6 64 [2] e9 78 }

  condition:
    any of them
}