rule TTP_XOR_WriteProcessMemory_93a7 {
  strings:
    $key_93a7 = { c4 d5 [2] f6 f7 [2] f0 c2 [2] de c2 [2] e1 de }

  condition:
    any of them
}