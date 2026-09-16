rule TTP_XOR_WriteProcessMemory_9155 {
  strings:
    $key_9155 = { c6 27 [2] f4 05 [2] f2 30 [2] dc 30 [2] e3 2c }

  condition:
    any of them
}