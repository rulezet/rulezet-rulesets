rule TTP_XOR_WriteProcessMemory_bf23 {
  strings:
    $key_bf23 = { e8 51 [2] da 73 [2] dc 46 [2] f2 46 [2] cd 5a }

  condition:
    any of them
}