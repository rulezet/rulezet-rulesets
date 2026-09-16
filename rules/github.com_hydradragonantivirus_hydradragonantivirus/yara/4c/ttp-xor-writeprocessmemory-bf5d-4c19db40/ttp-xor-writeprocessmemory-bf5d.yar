rule TTP_XOR_WriteProcessMemory_bf5d {
  strings:
    $key_bf5d = { e8 2f [2] da 0d [2] dc 38 [2] f2 38 [2] cd 24 }

  condition:
    any of them
}