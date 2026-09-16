rule TTP_XOR_WriteProcessMemory_90a7 {
  strings:
    $key_90a7 = { c7 d5 [2] f5 f7 [2] f3 c2 [2] dd c2 [2] e2 de }

  condition:
    any of them
}