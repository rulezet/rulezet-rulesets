rule TTP_XOR_WriteProcessMemory_bf15 {
  strings:
    $key_bf15 = { e8 67 [2] da 45 [2] dc 70 [2] f2 70 [2] cd 6c }

  condition:
    any of them
}