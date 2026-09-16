rule TTP_XOR_WriteProcessMemory_95a6 {
  strings:
    $key_95a6 = { c2 d4 [2] f0 f6 [2] f6 c3 [2] d8 c3 [2] e7 df }

  condition:
    any of them
}