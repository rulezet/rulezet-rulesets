rule TTP_XOR_WriteProcessMemory_85e4 {
  strings:
    $key_85e4 = { d2 96 [2] e0 b4 [2] e6 81 [2] c8 81 [2] f7 9d }

  condition:
    any of them
}