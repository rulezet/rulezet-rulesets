rule TTP_XOR_WriteProcessMemory_bf28 {
  strings:
    $key_bf28 = { e8 5a [2] da 78 [2] dc 4d [2] f2 4d [2] cd 51 }

  condition:
    any of them
}