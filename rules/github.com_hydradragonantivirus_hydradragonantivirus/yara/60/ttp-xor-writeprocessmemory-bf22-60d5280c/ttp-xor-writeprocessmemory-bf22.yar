rule TTP_XOR_WriteProcessMemory_bf22 {
  strings:
    $key_bf22 = { e8 50 [2] da 72 [2] dc 47 [2] f2 47 [2] cd 5b }

  condition:
    any of them
}