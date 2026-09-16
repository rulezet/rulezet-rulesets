rule TTP_XOR_WriteProcessMemory_8002 {
  strings:
    $key_8002 = { d7 70 [2] e5 52 [2] e3 67 [2] cd 67 [2] f2 7b }

  condition:
    any of them
}