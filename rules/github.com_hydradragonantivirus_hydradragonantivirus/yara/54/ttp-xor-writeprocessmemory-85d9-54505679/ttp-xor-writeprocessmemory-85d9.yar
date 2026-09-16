rule TTP_XOR_WriteProcessMemory_85d9 {
  strings:
    $key_85d9 = { d2 ab [2] e0 89 [2] e6 bc [2] c8 bc [2] f7 a0 }

  condition:
    any of them
}