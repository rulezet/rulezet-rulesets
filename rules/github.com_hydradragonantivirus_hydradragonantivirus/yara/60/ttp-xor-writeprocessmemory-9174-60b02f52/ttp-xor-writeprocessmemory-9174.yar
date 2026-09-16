rule TTP_XOR_WriteProcessMemory_9174 {
  strings:
    $key_9174 = { c6 06 [2] f4 24 [2] f2 11 [2] dc 11 [2] e3 0d }

  condition:
    any of them
}