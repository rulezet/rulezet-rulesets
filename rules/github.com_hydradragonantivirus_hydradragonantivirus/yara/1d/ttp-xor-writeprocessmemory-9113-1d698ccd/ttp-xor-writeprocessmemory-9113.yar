rule TTP_XOR_WriteProcessMemory_9113 {
  strings:
    $key_9113 = { c6 61 [2] f4 43 [2] f2 76 [2] dc 76 [2] e3 6a }

  condition:
    any of them
}