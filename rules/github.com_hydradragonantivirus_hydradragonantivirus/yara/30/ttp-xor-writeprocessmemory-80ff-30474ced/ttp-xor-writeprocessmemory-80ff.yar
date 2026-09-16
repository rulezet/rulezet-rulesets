rule TTP_XOR_WriteProcessMemory_80ff {
  strings:
    $key_80ff = { d7 8d [2] e5 af [2] e3 9a [2] cd 9a [2] f2 86 }

  condition:
    any of them
}