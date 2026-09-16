rule TTP_XOR_WriteProcessMemory_8034 {
  strings:
    $key_8034 = { d7 46 [2] e5 64 [2] e3 51 [2] cd 51 [2] f2 4d }

  condition:
    any of them
}