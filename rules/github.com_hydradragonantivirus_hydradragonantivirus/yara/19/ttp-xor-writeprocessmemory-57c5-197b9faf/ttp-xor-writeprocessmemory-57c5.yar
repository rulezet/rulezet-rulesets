rule TTP_XOR_WriteProcessMemory_57c5 {
  strings:
    $key_57c5 = { 00 b7 [2] 32 95 [2] 34 a0 [2] 1a a0 [2] 25 bc }

  condition:
    any of them
}