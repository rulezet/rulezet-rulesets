rule TTP_XOR_WriteProcessMemory_9da6 {
  strings:
    $key_9da6 = { ca d4 [2] f8 f6 [2] fe c3 [2] d0 c3 [2] ef df }

  condition:
    any of them
}