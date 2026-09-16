rule TTP_XOR_WriteProcessMemory_90d0 {
  strings:
    $key_90d0 = { c7 a2 [2] f5 80 [2] f3 b5 [2] dd b5 [2] e2 a9 }

  condition:
    any of them
}