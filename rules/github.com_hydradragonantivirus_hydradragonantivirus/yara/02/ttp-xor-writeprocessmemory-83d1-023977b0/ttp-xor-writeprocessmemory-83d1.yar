rule TTP_XOR_WriteProcessMemory_83d1 {
  strings:
    $key_83d1 = { d4 a3 [2] e6 81 [2] e0 b4 [2] ce b4 [2] f1 a8 }

  condition:
    any of them
}