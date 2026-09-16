rule TTP_XOR_WriteProcessMemory_9048 {
  strings:
    $key_9048 = { c7 3a [2] f5 18 [2] f3 2d [2] dd 2d [2] e2 31 }

  condition:
    any of them
}