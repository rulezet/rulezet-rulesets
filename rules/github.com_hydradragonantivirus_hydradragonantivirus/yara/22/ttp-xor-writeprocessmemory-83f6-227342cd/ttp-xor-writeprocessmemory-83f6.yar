rule TTP_XOR_WriteProcessMemory_83f6 {
  strings:
    $key_83f6 = { d4 84 [2] e6 a6 [2] e0 93 [2] ce 93 [2] f1 8f }

  condition:
    any of them
}