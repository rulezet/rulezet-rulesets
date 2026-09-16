rule TTP_XOR_WriteProcessMemory_82b9 {
  strings:
    $key_82b9 = { d5 cb [2] e7 e9 [2] e1 dc [2] cf dc [2] f0 c0 }

  condition:
    any of them
}