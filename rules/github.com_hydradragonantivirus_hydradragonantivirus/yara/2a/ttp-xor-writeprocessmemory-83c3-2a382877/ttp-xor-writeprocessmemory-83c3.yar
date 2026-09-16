rule TTP_XOR_WriteProcessMemory_83c3 {
  strings:
    $key_83c3 = { d4 b1 [2] e6 93 [2] e0 a6 [2] ce a6 [2] f1 ba }

  condition:
    any of them
}