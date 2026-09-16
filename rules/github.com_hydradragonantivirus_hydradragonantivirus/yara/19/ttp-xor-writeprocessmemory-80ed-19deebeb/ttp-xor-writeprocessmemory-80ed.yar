rule TTP_XOR_WriteProcessMemory_80ed {
  strings:
    $key_80ed = { d7 9f [2] e5 bd [2] e3 88 [2] cd 88 [2] f2 94 }

  condition:
    any of them
}