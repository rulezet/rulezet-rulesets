rule TTP_XOR_WriteProcessMemory_bf38 {
  strings:
    $key_bf38 = { e8 4a [2] da 68 [2] dc 5d [2] f2 5d [2] cd 41 }

  condition:
    any of them
}