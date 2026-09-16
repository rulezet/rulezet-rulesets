rule TTP_XOR_WriteProcessMemory_91e7 {
  strings:
    $key_91e7 = { c6 95 [2] f4 b7 [2] f2 82 [2] dc 82 [2] e3 9e }

  condition:
    any of them
}