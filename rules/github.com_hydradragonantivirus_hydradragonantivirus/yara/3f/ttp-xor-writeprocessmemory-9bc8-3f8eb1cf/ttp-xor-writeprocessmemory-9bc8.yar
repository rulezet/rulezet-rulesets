rule TTP_XOR_WriteProcessMemory_9bc8 {
  strings:
    $key_9bc8 = { cc ba [2] fe 98 [2] f8 ad [2] d6 ad [2] e9 b1 }

  condition:
    any of them
}