rule TTP_XOR_WriteProcessMemory_93b9 {
  strings:
    $key_93b9 = { c4 cb [2] f6 e9 [2] f0 dc [2] de dc [2] e1 c0 }

  condition:
    any of them
}