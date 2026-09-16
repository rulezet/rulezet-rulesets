rule TTP_XOR_WriteProcessMemory_83f2 {
  strings:
    $key_83f2 = { d4 80 [2] e6 a2 [2] e0 97 [2] ce 97 [2] f1 8b }

  condition:
    any of them
}