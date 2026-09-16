rule TTP_XOR_WriteProcessMemory_9148 {
  strings:
    $key_9148 = { c6 3a [2] f4 18 [2] f2 2d [2] dc 2d [2] e3 31 }

  condition:
    any of them
}