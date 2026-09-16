rule TTP_XOR_WriteProcessMemory_9778 {
  strings:
    $key_9778 = { c0 0a [2] f2 28 [2] f4 1d [2] da 1d [2] e5 01 }

  condition:
    any of them
}