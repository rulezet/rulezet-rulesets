rule TTP_XOR_WriteProcessMemory_8024 {
  strings:
    $key_8024 = { d7 56 [2] e5 74 [2] e3 41 [2] cd 41 [2] f2 5d }

  condition:
    any of them
}