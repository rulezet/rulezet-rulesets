rule TTP_XOR_WriteProcessMemory_bfdb {
  strings:
    $key_bfdb = { e8 a9 [2] da 8b [2] dc be [2] f2 be [2] cd a2 }

  condition:
    any of them
}