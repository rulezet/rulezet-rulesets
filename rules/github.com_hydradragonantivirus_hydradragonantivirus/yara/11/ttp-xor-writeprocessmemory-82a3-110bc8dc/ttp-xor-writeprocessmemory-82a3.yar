rule TTP_XOR_WriteProcessMemory_82a3 {
  strings:
    $key_82a3 = { d5 d1 [2] e7 f3 [2] e1 c6 [2] cf c6 [2] f0 da }

  condition:
    any of them
}