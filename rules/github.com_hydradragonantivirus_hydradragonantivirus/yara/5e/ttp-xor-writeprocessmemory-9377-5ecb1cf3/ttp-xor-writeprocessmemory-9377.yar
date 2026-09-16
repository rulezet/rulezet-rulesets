rule TTP_XOR_WriteProcessMemory_9377 {
  strings:
    $key_9377 = { c4 05 [2] f6 27 [2] f0 12 [2] de 12 [2] e1 0e }

  condition:
    any of them
}