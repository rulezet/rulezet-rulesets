rule TTP_XOR_WriteProcessMemory_9158 {
  strings:
    $key_9158 = { c6 2a [2] f4 08 [2] f2 3d [2] dc 3d [2] e3 21 }

  condition:
    any of them
}