rule TTP_XOR_WriteProcessMemory_9107 {
  strings:
    $key_9107 = { c6 75 [2] f4 57 [2] f2 62 [2] dc 62 [2] e3 7e }

  condition:
    any of them
}