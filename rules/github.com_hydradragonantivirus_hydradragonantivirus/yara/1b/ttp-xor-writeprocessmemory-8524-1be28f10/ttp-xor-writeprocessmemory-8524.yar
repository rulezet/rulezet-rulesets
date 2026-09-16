rule TTP_XOR_WriteProcessMemory_8524 {
  strings:
    $key_8524 = { d2 56 [2] e0 74 [2] e6 41 [2] c8 41 [2] f7 5d }

  condition:
    any of them
}