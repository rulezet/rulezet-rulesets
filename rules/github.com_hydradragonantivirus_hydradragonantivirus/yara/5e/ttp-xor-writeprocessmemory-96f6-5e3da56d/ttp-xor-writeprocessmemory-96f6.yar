rule TTP_XOR_WriteProcessMemory_96f6 {
  strings:
    $key_96f6 = { c1 84 [2] f3 a6 [2] f5 93 [2] db 93 [2] e4 8f }

  condition:
    any of them
}