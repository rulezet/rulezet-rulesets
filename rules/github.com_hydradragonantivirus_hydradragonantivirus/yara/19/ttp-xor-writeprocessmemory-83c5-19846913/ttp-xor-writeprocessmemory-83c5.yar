rule TTP_XOR_WriteProcessMemory_83c5 {
  strings:
    $key_83c5 = { d4 b7 [2] e6 95 [2] e0 a0 [2] ce a0 [2] f1 bc }

  condition:
    any of them
}