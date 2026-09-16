rule TTP_XOR_WriteProcessMemory_93f6 {
  strings:
    $key_93f6 = { c4 84 [2] f6 a6 [2] f0 93 [2] de 93 [2] e1 8f }

  condition:
    any of them
}