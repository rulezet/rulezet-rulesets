rule TTP_XOR_WriteProcessMemory_8554 {
  strings:
    $key_8554 = { d2 26 [2] e0 04 [2] e6 31 [2] c8 31 [2] f7 2d }

  condition:
    any of them
}