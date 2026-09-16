rule TTP_XOR_WriteProcessMemory_9126 {
  strings:
    $key_9126 = { c6 54 [2] f4 76 [2] f2 43 [2] dc 43 [2] e3 5f }

  condition:
    any of them
}