rule TTP_XOR_WriteProcessMemory_83f1 {
  strings:
    $key_83f1 = { d4 83 [2] e6 a1 [2] e0 94 [2] ce 94 [2] f1 88 }

  condition:
    any of them
}