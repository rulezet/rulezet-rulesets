rule TTP_XOR_WriteProcessMemory_bf0d {
  strings:
    $key_bf0d = { e8 7f [2] da 5d [2] dc 68 [2] f2 68 [2] cd 74 }

  condition:
    any of them
}