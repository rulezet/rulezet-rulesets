rule TTP_XOR_WriteProcessMemory_96b9 {
  strings:
    $key_96b9 = { c1 cb [2] f3 e9 [2] f5 dc [2] db dc [2] e4 c0 }

  condition:
    any of them
}