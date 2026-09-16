rule TTP_XOR_WriteProcessMemory_8390 {
  strings:
    $key_8390 = { d4 e2 [2] e6 c0 [2] e0 f5 [2] ce f5 [2] f1 e9 }

  condition:
    any of them
}