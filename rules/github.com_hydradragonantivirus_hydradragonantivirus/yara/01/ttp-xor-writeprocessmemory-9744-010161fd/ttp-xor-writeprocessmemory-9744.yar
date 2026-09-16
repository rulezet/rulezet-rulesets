rule TTP_XOR_WriteProcessMemory_9744 {
  strings:
    $key_9744 = { c0 36 [2] f2 14 [2] f4 21 [2] da 21 [2] e5 3d }

  condition:
    any of them
}