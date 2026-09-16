rule TTP_XOR_WriteProcessMemory_9132 {
  strings:
    $key_9132 = { c6 40 [2] f4 62 [2] f2 57 [2] dc 57 [2] e3 4b }

  condition:
    any of them
}