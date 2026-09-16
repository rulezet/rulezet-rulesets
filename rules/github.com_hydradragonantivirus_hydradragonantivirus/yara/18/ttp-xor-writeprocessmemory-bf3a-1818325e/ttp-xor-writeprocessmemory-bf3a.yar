rule TTP_XOR_WriteProcessMemory_bf3a {
  strings:
    $key_bf3a = { e8 48 [2] da 6a [2] dc 5f [2] f2 5f [2] cd 43 }

  condition:
    any of them
}