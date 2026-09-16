rule TTP_XOR_WriteProcessMemory_83e2 {
  strings:
    $key_83e2 = { d4 90 [2] e6 b2 [2] e0 87 [2] ce 87 [2] f1 9b }

  condition:
    any of them
}