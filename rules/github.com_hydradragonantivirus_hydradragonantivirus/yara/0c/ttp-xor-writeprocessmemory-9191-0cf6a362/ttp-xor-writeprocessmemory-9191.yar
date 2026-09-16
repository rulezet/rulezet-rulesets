rule TTP_XOR_WriteProcessMemory_9191 {
  strings:
    $key_9191 = { c6 e3 [2] f4 c1 [2] f2 f4 [2] dc f4 [2] e3 e8 }

  condition:
    any of them
}