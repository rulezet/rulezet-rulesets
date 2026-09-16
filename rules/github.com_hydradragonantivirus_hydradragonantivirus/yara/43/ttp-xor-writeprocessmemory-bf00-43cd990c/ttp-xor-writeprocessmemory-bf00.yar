rule TTP_XOR_WriteProcessMemory_bf00 {
  strings:
    $key_bf00 = { e8 72 [2] da 50 [2] dc 65 [2] f2 65 [2] cd 79 }

  condition:
    any of them
}