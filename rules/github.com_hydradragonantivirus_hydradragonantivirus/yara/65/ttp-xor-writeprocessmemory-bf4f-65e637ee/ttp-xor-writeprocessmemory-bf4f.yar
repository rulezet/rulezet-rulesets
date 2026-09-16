rule TTP_XOR_WriteProcessMemory_bf4f {
  strings:
    $key_bf4f = { e8 3d [2] da 1f [2] dc 2a [2] f2 2a [2] cd 36 }

  condition:
    any of them
}