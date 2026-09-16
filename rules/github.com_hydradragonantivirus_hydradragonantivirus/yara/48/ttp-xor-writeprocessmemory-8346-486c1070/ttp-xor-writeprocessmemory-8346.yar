rule TTP_XOR_WriteProcessMemory_8346 {
  strings:
    $key_8346 = { d4 34 [2] e6 16 [2] e0 23 [2] ce 23 [2] f1 3f }

  condition:
    any of them
}