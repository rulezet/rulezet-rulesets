rule TTP_XOR_WriteProcessMemory_8504 {
  strings:
    $key_8504 = { d2 76 [2] e0 54 [2] e6 61 [2] c8 61 [2] f7 7d }

  condition:
    any of them
}