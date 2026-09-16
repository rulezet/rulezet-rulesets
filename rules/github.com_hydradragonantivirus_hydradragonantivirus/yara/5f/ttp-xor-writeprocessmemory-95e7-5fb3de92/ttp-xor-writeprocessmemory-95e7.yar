rule TTP_XOR_WriteProcessMemory_95e7 {
  strings:
    $key_95e7 = { c2 95 [2] f0 b7 [2] f6 82 [2] d8 82 [2] e7 9e }

  condition:
    any of them
}