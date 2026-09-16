rule TTP_XOR_WriteProcessMemory_bf7f {
  strings:
    $key_bf7f = { e8 0d [2] da 2f [2] dc 1a [2] f2 1a [2] cd 06 }

  condition:
    any of them
}