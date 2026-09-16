rule TTP_XOR_WriteProcessMemory_8044 {
  strings:
    $key_8044 = { d7 36 [2] e5 14 [2] e3 21 [2] cd 21 [2] f2 3d }

  condition:
    any of them
}