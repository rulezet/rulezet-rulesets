rule TTP_XOR_WriteProcessMemory_96f3 {
  strings:
    $key_96f3 = { c1 81 [2] f3 a3 [2] f5 96 [2] db 96 [2] e4 8a }

  condition:
    any of them
}