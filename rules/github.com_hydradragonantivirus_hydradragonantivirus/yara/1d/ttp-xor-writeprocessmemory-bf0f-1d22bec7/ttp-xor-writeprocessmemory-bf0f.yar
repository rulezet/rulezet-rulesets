rule TTP_XOR_WriteProcessMemory_bf0f {
  strings:
    $key_bf0f = { e8 7d [2] da 5f [2] dc 6a [2] f2 6a [2] cd 76 }

  condition:
    any of them
}