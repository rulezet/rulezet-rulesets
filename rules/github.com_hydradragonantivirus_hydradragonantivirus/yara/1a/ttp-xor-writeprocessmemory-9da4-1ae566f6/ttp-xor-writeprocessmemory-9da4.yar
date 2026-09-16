rule TTP_XOR_WriteProcessMemory_9da4 {
  strings:
    $key_9da4 = { ca d6 [2] f8 f4 [2] fe c1 [2] d0 c1 [2] ef dd }

  condition:
    any of them
}