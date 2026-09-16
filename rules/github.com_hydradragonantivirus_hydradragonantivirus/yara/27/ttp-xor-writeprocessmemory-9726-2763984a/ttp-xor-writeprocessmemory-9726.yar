rule TTP_XOR_WriteProcessMemory_9726 {
  strings:
    $key_9726 = { c0 54 [2] f2 76 [2] f4 43 [2] da 43 [2] e5 5f }

  condition:
    any of them
}