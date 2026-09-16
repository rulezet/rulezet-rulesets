rule TTP_XOR_WriteProcessMemory_81c0 {
  strings:
    $key_81c0 = { d6 b2 [2] e4 90 [2] e2 a5 [2] cc a5 [2] f3 b9 }

  condition:
    any of them
}