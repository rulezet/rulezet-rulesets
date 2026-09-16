rule TTP_XOR_WriteProcessMemory_9178 {
  strings:
    $key_9178 = { c6 0a [2] f4 28 [2] f2 1d [2] dc 1d [2] e3 01 }

  condition:
    any of them
}