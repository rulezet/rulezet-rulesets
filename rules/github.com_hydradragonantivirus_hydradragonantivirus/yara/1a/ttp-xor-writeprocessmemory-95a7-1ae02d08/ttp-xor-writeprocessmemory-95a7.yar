rule TTP_XOR_WriteProcessMemory_95a7 {
  strings:
    $key_95a7 = { c2 d5 [2] f0 f7 [2] f6 c2 [2] d8 c2 [2] e7 de }

  condition:
    any of them
}