rule TTP_XOR_WriteProcessMemory_91e4 {
  strings:
    $key_91e4 = { c6 96 [2] f4 b4 [2] f2 81 [2] dc 81 [2] e3 9d }

  condition:
    any of them
}