rule TTP_XOR_WriteProcessMemory_8016 {
  strings:
    $key_8016 = { d7 64 [2] e5 46 [2] e3 73 [2] cd 73 [2] f2 6f }

  condition:
    any of them
}