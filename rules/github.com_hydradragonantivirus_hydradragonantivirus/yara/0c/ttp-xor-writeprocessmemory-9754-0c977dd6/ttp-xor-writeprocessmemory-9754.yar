rule TTP_XOR_WriteProcessMemory_9754 {
  strings:
    $key_9754 = { c0 26 [2] f2 04 [2] f4 31 [2] da 31 [2] e5 2d }

  condition:
    any of them
}