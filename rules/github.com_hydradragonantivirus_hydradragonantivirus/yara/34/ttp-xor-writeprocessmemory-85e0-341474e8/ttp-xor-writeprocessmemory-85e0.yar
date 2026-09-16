rule TTP_XOR_WriteProcessMemory_85e0 {
  strings:
    $key_85e0 = { d2 92 [2] e0 b0 [2] e6 85 [2] c8 85 [2] f7 99 }

  condition:
    any of them
}