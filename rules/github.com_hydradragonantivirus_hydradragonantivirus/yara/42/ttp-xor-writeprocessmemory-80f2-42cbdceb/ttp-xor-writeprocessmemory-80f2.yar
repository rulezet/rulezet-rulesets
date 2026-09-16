rule TTP_XOR_WriteProcessMemory_80f2 {
  strings:
    $key_80f2 = { d7 80 [2] e5 a2 [2] e3 97 [2] cd 97 [2] f2 8b }

  condition:
    any of them
}