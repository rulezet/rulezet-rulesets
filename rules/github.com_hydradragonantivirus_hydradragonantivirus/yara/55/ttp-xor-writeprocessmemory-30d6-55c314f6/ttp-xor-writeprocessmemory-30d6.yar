rule TTP_XOR_WriteProcessMemory_30d6 {
  strings:
    $key_30d6 = { 67 a4 [2] 55 86 [2] 53 b3 [2] 7d b3 [2] 42 af }

  condition:
    any of them
}