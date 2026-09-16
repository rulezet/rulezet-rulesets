rule TTP_XOR_WriteProcessMemory_9738 {
  strings:
    $key_9738 = { c0 4a [2] f2 68 [2] f4 5d [2] da 5d [2] e5 41 }

  condition:
    any of them
}