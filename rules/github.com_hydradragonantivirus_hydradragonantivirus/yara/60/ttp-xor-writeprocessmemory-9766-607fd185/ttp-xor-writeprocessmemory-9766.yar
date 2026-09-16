rule TTP_XOR_WriteProcessMemory_9766 {
  strings:
    $key_9766 = { c0 14 [2] f2 36 [2] f4 03 [2] da 03 [2] e5 1f }

  condition:
    any of them
}