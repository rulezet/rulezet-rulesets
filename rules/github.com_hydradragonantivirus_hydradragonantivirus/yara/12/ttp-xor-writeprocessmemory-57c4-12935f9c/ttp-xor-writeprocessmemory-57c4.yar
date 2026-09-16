rule TTP_XOR_WriteProcessMemory_57c4 {
  strings:
    $key_57c4 = { 00 b6 [2] 32 94 [2] 34 a1 [2] 1a a1 [2] 25 bd }

  condition:
    any of them
}