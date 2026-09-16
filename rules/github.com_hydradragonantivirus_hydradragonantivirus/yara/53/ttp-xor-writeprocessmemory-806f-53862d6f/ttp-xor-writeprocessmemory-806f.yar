rule TTP_XOR_WriteProcessMemory_806f {
  strings:
    $key_806f = { d7 1d [2] e5 3f [2] e3 0a [2] cd 0a [2] f2 16 }

  condition:
    any of them
}