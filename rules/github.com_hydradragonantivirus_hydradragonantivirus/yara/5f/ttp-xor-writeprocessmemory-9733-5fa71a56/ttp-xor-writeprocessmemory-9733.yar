rule TTP_XOR_WriteProcessMemory_9733 {
  strings:
    $key_9733 = { c0 41 [2] f2 63 [2] f4 56 [2] da 56 [2] e5 4a }

  condition:
    any of them
}