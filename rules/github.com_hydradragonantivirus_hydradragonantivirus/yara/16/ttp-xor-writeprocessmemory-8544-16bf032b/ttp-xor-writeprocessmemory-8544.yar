rule TTP_XOR_WriteProcessMemory_8544 {
  strings:
    $key_8544 = { d2 36 [2] e0 14 [2] e6 21 [2] c8 21 [2] f7 3d }

  condition:
    any of them
}