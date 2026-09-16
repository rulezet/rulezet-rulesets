rule TTP_XOR_WriteProcessMemory_92a3 {
  strings:
    $key_92a3 = { c5 d1 [2] f7 f3 [2] f1 c6 [2] df c6 [2] e0 da }

  condition:
    any of them
}