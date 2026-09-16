rule TTP_XOR_WriteProcessMemory_bff9 {
  strings:
    $key_bff9 = { e8 8b [2] da a9 [2] dc 9c [2] f2 9c [2] cd 80 }

  condition:
    any of them
}