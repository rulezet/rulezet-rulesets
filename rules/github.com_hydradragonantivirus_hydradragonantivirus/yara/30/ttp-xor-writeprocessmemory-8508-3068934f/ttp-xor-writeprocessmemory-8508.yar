rule TTP_XOR_WriteProcessMemory_8508 {
  strings:
    $key_8508 = { d2 7a [2] e0 58 [2] e6 6d [2] c8 6d [2] f7 71 }

  condition:
    any of them
}