rule TTP_XOR_WriteProcessMemory_bfda {
  strings:
    $key_bfda = { e8 a8 [2] da 8a [2] dc bf [2] f2 bf [2] cd a3 }

  condition:
    any of them
}