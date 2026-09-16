rule TTP_XOR_WriteProcessMemory_9106 {
  strings:
    $key_9106 = { c6 74 [2] f4 56 [2] f2 63 [2] dc 63 [2] e3 7f }

  condition:
    any of them
}