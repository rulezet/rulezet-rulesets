rule TTP_XOR_WriteProcessMemory_bf06 {
  strings:
    $key_bf06 = { e8 74 [2] da 56 [2] dc 63 [2] f2 63 [2] cd 7f }

  condition:
    any of them
}