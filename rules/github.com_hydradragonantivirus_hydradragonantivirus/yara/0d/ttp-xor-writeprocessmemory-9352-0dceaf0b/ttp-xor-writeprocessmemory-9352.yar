rule TTP_XOR_WriteProcessMemory_9352 {
  strings:
    $key_9352 = { c4 20 [2] f6 02 [2] f0 37 [2] de 37 [2] e1 2b }

  condition:
    any of them
}