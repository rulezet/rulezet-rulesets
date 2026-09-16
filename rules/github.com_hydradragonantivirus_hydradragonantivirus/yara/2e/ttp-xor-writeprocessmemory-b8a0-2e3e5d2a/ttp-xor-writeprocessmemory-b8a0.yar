rule TTP_XOR_WriteProcessMemory_b8a0 {
  strings:
    $key_b8a0 = { ef d2 [2] dd f0 [2] db c5 [2] f5 c5 [2] ca d9 }

  condition:
    any of them
}