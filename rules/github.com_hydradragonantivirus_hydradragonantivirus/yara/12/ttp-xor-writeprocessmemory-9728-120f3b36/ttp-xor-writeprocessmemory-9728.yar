rule TTP_XOR_WriteProcessMemory_9728 {
  strings:
    $key_9728 = { c0 5a [2] f2 78 [2] f4 4d [2] da 4d [2] e5 51 }

  condition:
    any of them
}