rule TTP_XOR_WriteProcessMemory_8022 {
  strings:
    $key_8022 = { d7 50 [2] e5 72 [2] e3 47 [2] cd 47 [2] f2 5b }

  condition:
    any of them
}