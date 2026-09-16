rule TTP_XOR_WriteProcessMemory_83e7 {
  strings:
    $key_83e7 = { d4 95 [2] e6 b7 [2] e0 82 [2] ce 82 [2] f1 9e }

  condition:
    any of them
}