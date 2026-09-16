rule TTP_XOR_WriteProcessMemory_8038 {
  strings:
    $key_8038 = { d7 4a [2] e5 68 [2] e3 5d [2] cd 5d [2] f2 41 }

  condition:
    any of them
}