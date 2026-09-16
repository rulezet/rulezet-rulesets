rule TTP_XOR_WriteProcessMemory_bf11 {
  strings:
    $key_bf11 = { e8 63 [2] da 41 [2] dc 74 [2] f2 74 [2] cd 68 }

  condition:
    any of them
}