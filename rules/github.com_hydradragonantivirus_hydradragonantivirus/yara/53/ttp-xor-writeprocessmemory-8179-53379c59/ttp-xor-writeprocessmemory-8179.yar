rule TTP_XOR_WriteProcessMemory_8179 {
  strings:
    $key_8179 = { d6 0b [2] e4 29 [2] e2 1c [2] cc 1c [2] f3 00 }

  condition:
    any of them
}