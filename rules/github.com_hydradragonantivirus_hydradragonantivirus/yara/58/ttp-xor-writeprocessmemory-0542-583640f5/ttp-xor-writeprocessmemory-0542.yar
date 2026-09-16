rule TTP_XOR_WriteProcessMemory_0542 {
  strings:
    $key_0542 = { 52 30 [2] 60 12 [2] 66 27 [2] 48 27 [2] 77 3b }

  condition:
    any of them
}