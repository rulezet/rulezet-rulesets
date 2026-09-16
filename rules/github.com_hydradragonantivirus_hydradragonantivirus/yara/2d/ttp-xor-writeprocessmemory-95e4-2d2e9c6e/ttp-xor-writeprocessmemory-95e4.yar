rule TTP_XOR_WriteProcessMemory_95e4 {
  strings:
    $key_95e4 = { c2 96 [2] f0 b4 [2] f6 81 [2] d8 81 [2] e7 9d }

  condition:
    any of them
}