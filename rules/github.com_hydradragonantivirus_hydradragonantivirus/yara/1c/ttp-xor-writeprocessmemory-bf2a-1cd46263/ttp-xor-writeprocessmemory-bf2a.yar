rule TTP_XOR_WriteProcessMemory_bf2a {
  strings:
    $key_bf2a = { e8 58 [2] da 7a [2] dc 4f [2] f2 4f [2] cd 53 }

  condition:
    any of them
}