rule TTP_XOR_WriteProcessMemory_8028 {
  strings:
    $key_8028 = { d7 5a [2] e5 78 [2] e3 4d [2] cd 4d [2] f2 51 }

  condition:
    any of them
}