rule TTP_XOR_WriteProcessMemory_82f2 {
  strings:
    $key_82f2 = { d5 80 [2] e7 a2 [2] e1 97 [2] cf 97 [2] f0 8b }

  condition:
    any of them
}