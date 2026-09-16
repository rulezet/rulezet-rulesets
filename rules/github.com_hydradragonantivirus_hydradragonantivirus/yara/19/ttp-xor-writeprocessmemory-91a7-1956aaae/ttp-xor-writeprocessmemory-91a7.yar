rule TTP_XOR_WriteProcessMemory_91a7 {
  strings:
    $key_91a7 = { c6 d5 [2] f4 f7 [2] f2 c2 [2] dc c2 [2] e3 de }

  condition:
    any of them
}