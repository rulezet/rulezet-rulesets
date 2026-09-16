rule TTP_XOR_WriteProcessMemory_96a6 {
  strings:
    $key_96a6 = { c1 d4 [2] f3 f6 [2] f5 c3 [2] db c3 [2] e4 df }

  condition:
    any of them
}