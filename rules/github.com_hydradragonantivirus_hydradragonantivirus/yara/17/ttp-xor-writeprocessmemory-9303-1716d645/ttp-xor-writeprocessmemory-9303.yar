rule TTP_XOR_WriteProcessMemory_9303 {
  strings:
    $key_9303 = { c4 71 [2] f6 53 [2] f0 66 [2] de 66 [2] e1 7a }

  condition:
    any of them
}