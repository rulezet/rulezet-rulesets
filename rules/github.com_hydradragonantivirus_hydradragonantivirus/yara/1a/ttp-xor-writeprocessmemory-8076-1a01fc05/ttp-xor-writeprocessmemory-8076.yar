rule TTP_XOR_WriteProcessMemory_8076 {
  strings:
    $key_8076 = { d7 04 [2] e5 26 [2] e3 13 [2] cd 13 [2] f2 0f }

  condition:
    any of them
}