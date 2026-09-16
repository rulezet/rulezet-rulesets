rule TTP_XOR_WriteProcessMemory_96c3 {
  strings:
    $key_96c3 = { c1 b1 [2] f3 93 [2] f5 a6 [2] db a6 [2] e4 ba }

  condition:
    any of them
}