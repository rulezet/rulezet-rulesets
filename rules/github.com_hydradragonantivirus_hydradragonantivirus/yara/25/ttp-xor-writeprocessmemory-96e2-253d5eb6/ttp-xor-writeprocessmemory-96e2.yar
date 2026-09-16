rule TTP_XOR_WriteProcessMemory_96e2 {
  strings:
    $key_96e2 = { c1 90 [2] f3 b2 [2] f5 87 [2] db 87 [2] e4 9b }

  condition:
    any of them
}