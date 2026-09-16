rule TTP_XOR_WriteProcessMemory_80e8 {
  strings:
    $key_80e8 = { d7 9a [2] e5 b8 [2] e3 8d [2] cd 8d [2] f2 91 }

  condition:
    any of them
}