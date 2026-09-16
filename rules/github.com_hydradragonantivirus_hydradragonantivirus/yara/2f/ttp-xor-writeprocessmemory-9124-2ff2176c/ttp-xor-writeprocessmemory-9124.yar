rule TTP_XOR_WriteProcessMemory_9124 {
  strings:
    $key_9124 = { c6 56 [2] f4 74 [2] f2 41 [2] dc 41 [2] e3 5d }

  condition:
    any of them
}