rule TTP_XOR_WriteProcessMemory_b8a4 {
  strings:
    $key_b8a4 = { ef d6 [2] dd f4 [2] db c1 [2] f5 c1 [2] ca dd }

  condition:
    any of them
}