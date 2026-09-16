rule TTP_XOR_WriteProcessMemory_9354 {
  strings:
    $key_9354 = { c4 26 [2] f6 04 [2] f0 31 [2] de 31 [2] e1 2d }

  condition:
    any of them
}