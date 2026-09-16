rule TTP_XOR_WriteProcessMemory_bfe8 {
  strings:
    $key_bfe8 = { e8 9a [2] da b8 [2] dc 8d [2] f2 8d [2] cd 91 }

  condition:
    any of them
}