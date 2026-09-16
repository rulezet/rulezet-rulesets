rule TTP_XOR_WriteProcessMemory_90d1 {
  strings:
    $key_90d1 = { c7 a3 [2] f5 81 [2] f3 b4 [2] dd b4 [2] e2 a8 }

  condition:
    any of them
}