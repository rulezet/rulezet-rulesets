rule TTP_XOR_WriteProcessMemory_9518 {
  strings:
    $key_9518 = { c2 6a [2] f0 48 [2] f6 7d [2] d8 7d [2] e7 61 }

  condition:
    any of them
}