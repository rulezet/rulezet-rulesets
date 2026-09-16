rule TTP_XOR_WriteProcessMemory_bf1a {
  strings:
    $key_bf1a = { e8 68 [2] da 4a [2] dc 7f [2] f2 7f [2] cd 63 }

  condition:
    any of them
}