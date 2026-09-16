rule TTP_XOR_WriteProcessMemory_80e5 {
  strings:
    $key_80e5 = { d7 97 [2] e5 b5 [2] e3 80 [2] cd 80 [2] f2 9c }

  condition:
    any of them
}