rule TTP_XOR_WriteProcessMemory_bf20 {
  strings:
    $key_bf20 = { e8 52 [2] da 70 [2] dc 45 [2] f2 45 [2] cd 59 }

  condition:
    any of them
}