rule TTP_XOR_WriteProcessMemory_82e2 {
  strings:
    $key_82e2 = { d5 90 [2] e7 b2 [2] e1 87 [2] cf 87 [2] f0 9b }

  condition:
    any of them
}