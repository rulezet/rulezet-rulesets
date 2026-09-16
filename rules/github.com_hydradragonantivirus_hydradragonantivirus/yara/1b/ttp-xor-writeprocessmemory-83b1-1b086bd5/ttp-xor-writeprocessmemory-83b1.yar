rule TTP_XOR_WriteProcessMemory_83b1 {
  strings:
    $key_83b1 = { d4 c3 [2] e6 e1 [2] e0 d4 [2] ce d4 [2] f1 c8 }

  condition:
    any of them
}