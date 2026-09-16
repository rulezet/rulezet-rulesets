rule TTP_XOR_WriteProcessMemory_8646 {
  strings:
    $key_8646 = { d1 34 [2] e3 16 [2] e5 23 [2] cb 23 [2] f4 3f }

  condition:
    any of them
}