rule TTP_XOR_WriteProcessMemory_8018 {
  strings:
    $key_8018 = { d7 6a [2] e5 48 [2] e3 7d [2] cd 7d [2] f2 61 }

  condition:
    any of them
}