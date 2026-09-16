rule TTP_XOR_WriteProcessMemory_bfe3 {
  strings:
    $key_bfe3 = { e8 91 [2] da b3 [2] dc 86 [2] f2 86 [2] cd 9a }

  condition:
    any of them
}