rule TTP_XOR_WriteProcessMemory_90d2 {
  strings:
    $key_90d2 = { c7 a0 [2] f5 82 [2] f3 b7 [2] dd b7 [2] e2 ab }

  condition:
    any of them
}