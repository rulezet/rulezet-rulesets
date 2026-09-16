rule TTP_XOR_WriteProcessMemory_bff6 {
  strings:
    $key_bff6 = { e8 84 [2] da a6 [2] dc 93 [2] f2 93 [2] cd 8f }

  condition:
    any of them
}