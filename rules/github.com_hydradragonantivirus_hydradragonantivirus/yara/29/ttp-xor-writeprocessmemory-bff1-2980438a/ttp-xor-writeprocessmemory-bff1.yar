rule TTP_XOR_WriteProcessMemory_bff1 {
  strings:
    $key_bff1 = { e8 83 [2] da a1 [2] dc 94 [2] f2 94 [2] cd 88 }

  condition:
    any of them
}