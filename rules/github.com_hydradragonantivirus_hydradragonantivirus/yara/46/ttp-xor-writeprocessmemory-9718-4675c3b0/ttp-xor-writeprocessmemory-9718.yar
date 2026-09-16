rule TTP_XOR_WriteProcessMemory_9718 {
  strings:
    $key_9718 = { c0 6a [2] f2 48 [2] f4 7d [2] da 7d [2] e5 61 }

  condition:
    any of them
}