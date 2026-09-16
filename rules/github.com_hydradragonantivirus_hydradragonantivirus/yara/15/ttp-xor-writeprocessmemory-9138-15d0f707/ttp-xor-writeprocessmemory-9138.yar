rule TTP_XOR_WriteProcessMemory_9138 {
  strings:
    $key_9138 = { c6 4a [2] f4 68 [2] f2 5d [2] dc 5d [2] e3 41 }

  condition:
    any of them
}