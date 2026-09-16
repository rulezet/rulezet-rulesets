rule TTP_XOR_WriteProcessMemory_bf3f {
  strings:
    $key_bf3f = { e8 4d [2] da 6f [2] dc 5a [2] f2 5a [2] cd 46 }

  condition:
    any of them
}