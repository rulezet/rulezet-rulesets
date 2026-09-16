rule TTP_XOR_WriteProcessMemory_93d4 {
  strings:
    $key_93d4 = { c4 a6 [2] f6 84 [2] f0 b1 [2] de b1 [2] e1 ad }

  condition:
    any of them
}