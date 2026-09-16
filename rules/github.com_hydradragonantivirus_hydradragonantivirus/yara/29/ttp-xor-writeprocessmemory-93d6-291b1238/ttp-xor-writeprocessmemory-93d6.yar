rule TTP_XOR_WriteProcessMemory_93d6 {
  strings:
    $key_93d6 = { c4 a4 [2] f6 86 [2] f0 b3 [2] de b3 [2] e1 af }

  condition:
    any of them
}