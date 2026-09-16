rule TTP_XOR_WriteProcessMemory_bff8 {
  strings:
    $key_bff8 = { e8 8a [2] da a8 [2] dc 9d [2] f2 9d [2] cd 81 }

  condition:
    any of them
}