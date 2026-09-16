rule TTP_XOR_WriteProcessMemory_82f6 {
  strings:
    $key_82f6 = { d5 84 [2] e7 a6 [2] e1 93 [2] cf 93 [2] f0 8f }

  condition:
    any of them
}