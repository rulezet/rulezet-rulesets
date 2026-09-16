rule TTP_XOR_WriteProcessMemory_92a6 {
  strings:
    $key_92a6 = { c5 d4 [2] f7 f6 [2] f1 c3 [2] df c3 [2] e0 df }

  condition:
    any of them
}