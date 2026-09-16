rule TTP_XOR_WriteProcessMemory_9122 {
  strings:
    $key_9122 = { c6 50 [2] f4 72 [2] f2 47 [2] dc 47 [2] e3 5b }

  condition:
    any of them
}