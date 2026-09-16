rule TTP_XOR_WriteProcessMemory_bf2f {
  strings:
    $key_bf2f = { e8 5d [2] da 7f [2] dc 4a [2] f2 4a [2] cd 56 }

  condition:
    any of them
}