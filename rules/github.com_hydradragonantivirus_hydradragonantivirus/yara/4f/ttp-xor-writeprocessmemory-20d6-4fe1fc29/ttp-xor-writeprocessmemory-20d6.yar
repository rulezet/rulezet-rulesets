rule TTP_XOR_WriteProcessMemory_20d6 {
  strings:
    $key_20d6 = { 77 a4 [2] 45 86 [2] 43 b3 [2] 6d b3 [2] 52 af }

  condition:
    any of them
}