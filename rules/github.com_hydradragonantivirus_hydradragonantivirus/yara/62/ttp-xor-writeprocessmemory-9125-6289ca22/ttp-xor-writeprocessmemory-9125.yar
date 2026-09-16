rule TTP_XOR_WriteProcessMemory_9125 {
  strings:
    $key_9125 = { c6 57 [2] f4 75 [2] f2 40 [2] dc 40 [2] e3 5c }

  condition:
    any of them
}