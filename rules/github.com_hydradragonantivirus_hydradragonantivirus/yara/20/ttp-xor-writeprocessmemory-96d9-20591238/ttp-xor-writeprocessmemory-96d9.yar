rule TTP_XOR_WriteProcessMemory_96d9 {
  strings:
    $key_96d9 = { c1 ab [2] f3 89 [2] f5 bc [2] db bc [2] e4 a0 }

  condition:
    any of them
}