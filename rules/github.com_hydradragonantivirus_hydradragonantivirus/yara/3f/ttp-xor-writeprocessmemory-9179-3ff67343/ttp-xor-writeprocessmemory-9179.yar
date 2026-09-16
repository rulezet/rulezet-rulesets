rule TTP_XOR_WriteProcessMemory_9179 {
  strings:
    $key_9179 = { c6 0b [2] f4 29 [2] f2 1c [2] dc 1c [2] e3 00 }

  condition:
    any of them
}