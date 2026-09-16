rule TTP_XOR_WriteProcessMemory_90a3 {
  strings:
    $key_90a3 = { c7 d1 [2] f5 f3 [2] f3 c6 [2] dd c6 [2] e2 da }

  condition:
    any of them
}