rule TTP_XOR_WriteProcessMemory_9bc2 {
  strings:
    $key_9bc2 = { cc b0 [2] fe 92 [2] f8 a7 [2] d6 a7 [2] e9 bb }

  condition:
    any of them
}