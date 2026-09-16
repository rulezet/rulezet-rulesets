rule TTP_XOR_WriteProcessMemory_9366 {
  strings:
    $key_9366 = { c4 14 [2] f6 36 [2] f0 03 [2] de 03 [2] e1 1f }

  condition:
    any of them
}