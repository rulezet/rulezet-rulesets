rule TTP_XOR_WriteProcessMemory_9102 {
  strings:
    $key_9102 = { c6 70 [2] f4 52 [2] f2 67 [2] dc 67 [2] e3 7b }

  condition:
    any of them
}