rule TTP_XOR_WriteProcessMemory_85f7 {
  strings:
    $key_85f7 = { d2 85 [2] e0 a7 [2] e6 92 [2] c8 92 [2] f7 8e }

  condition:
    any of them
}