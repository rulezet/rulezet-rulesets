rule TTP_XOR_WriteProcessMemory_8656 {
  strings:
    $key_8656 = { d1 24 [2] e3 06 [2] e5 33 [2] cb 33 [2] f4 2f }

  condition:
    any of them
}