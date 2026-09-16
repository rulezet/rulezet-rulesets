rule TTP_XOR_WriteProcessMemory_9131 {
  strings:
    $key_9131 = { c6 43 [2] f4 61 [2] f2 54 [2] dc 54 [2] e3 48 }

  condition:
    any of them
}