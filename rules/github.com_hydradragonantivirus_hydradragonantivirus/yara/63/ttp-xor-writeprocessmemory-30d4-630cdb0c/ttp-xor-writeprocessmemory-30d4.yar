rule TTP_XOR_WriteProcessMemory_30d4 {
  strings:
    $key_30d4 = { 67 a6 [2] 55 84 [2] 53 b1 [2] 7d b1 [2] 42 ad }

  condition:
    any of them
}