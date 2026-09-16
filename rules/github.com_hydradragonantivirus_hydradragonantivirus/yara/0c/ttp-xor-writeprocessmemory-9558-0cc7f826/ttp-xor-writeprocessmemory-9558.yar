rule TTP_XOR_WriteProcessMemory_9558 {
  strings:
    $key_9558 = { c2 2a [2] f0 08 [2] f6 3d [2] d8 3d [2] e7 21 }

  condition:
    any of them
}