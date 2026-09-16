rule TTP_XOR_WriteProcessMemory_bf7a {
  strings:
    $key_bf7a = { e8 08 [2] da 2a [2] dc 1f [2] f2 1f [2] cd 03 }

  condition:
    any of them
}