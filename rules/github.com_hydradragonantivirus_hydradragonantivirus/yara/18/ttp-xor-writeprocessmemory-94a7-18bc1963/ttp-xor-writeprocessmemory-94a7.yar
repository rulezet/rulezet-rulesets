rule TTP_XOR_WriteProcessMemory_94a7 {
  strings:
    $key_94a7 = { c3 d5 [2] f1 f7 [2] f7 c2 [2] d9 c2 [2] e6 de }

  condition:
    any of them
}