rule TTP_XOR_WriteProcessMemory_93e6 {
  strings:
    $key_93e6 = { c4 94 [2] f6 b6 [2] f0 83 [2] de 83 [2] e1 9f }

  condition:
    any of them
}