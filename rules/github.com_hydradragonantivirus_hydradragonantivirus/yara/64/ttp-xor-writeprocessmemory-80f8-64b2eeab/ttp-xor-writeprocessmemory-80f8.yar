rule TTP_XOR_WriteProcessMemory_80f8 {
  strings:
    $key_80f8 = { d7 8a [2] e5 a8 [2] e3 9d [2] cd 9d [2] f2 81 }

  condition:
    any of them
}