rule TTP_XOR_WriteProcessMemory_83d9 {
  strings:
    $key_83d9 = { d4 ab [2] e6 89 [2] e0 bc [2] ce bc [2] f1 a0 }

  condition:
    any of them
}