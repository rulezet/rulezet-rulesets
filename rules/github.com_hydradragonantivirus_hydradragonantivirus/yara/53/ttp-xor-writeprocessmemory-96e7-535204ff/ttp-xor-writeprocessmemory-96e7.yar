rule TTP_XOR_WriteProcessMemory_96e7 {
  strings:
    $key_96e7 = { c1 95 [2] f3 b7 [2] f5 82 [2] db 82 [2] e4 9e }

  condition:
    any of them
}