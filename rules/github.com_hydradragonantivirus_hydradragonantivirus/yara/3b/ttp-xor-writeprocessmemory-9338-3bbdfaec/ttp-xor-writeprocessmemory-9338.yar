rule TTP_XOR_WriteProcessMemory_9338 {
  strings:
    $key_9338 = { c4 4a [2] f6 68 [2] f0 5d [2] de 5d [2] e1 41 }

  condition:
    any of them
}