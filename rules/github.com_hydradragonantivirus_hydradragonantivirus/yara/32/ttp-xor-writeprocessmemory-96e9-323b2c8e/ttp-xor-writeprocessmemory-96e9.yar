rule TTP_XOR_WriteProcessMemory_96e9 {
  strings:
    $key_96e9 = { c1 9b [2] f3 b9 [2] f5 8c [2] db 8c [2] e4 90 }

  condition:
    any of them
}