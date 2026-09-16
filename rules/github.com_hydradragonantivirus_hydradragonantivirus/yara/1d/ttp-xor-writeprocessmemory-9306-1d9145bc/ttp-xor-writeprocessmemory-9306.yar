rule TTP_XOR_WriteProcessMemory_9306 {
  strings:
    $key_9306 = { c4 74 [2] f6 56 [2] f0 63 [2] de 63 [2] e1 7f }

  condition:
    any of them
}