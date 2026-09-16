rule TTP_XOR_WriteProcessMemory_90a5 {
  strings:
    $key_90a5 = { c7 d7 [2] f5 f5 [2] f3 c0 [2] dd c0 [2] e2 dc }

  condition:
    any of them
}