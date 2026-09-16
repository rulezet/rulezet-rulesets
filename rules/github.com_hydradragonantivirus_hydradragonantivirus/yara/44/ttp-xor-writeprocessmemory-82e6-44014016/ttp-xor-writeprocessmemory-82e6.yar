rule TTP_XOR_WriteProcessMemory_82e6 {
  strings:
    $key_82e6 = { d5 94 [2] e7 b6 [2] e1 83 [2] cf 83 [2] f0 9f }

  condition:
    any of them
}