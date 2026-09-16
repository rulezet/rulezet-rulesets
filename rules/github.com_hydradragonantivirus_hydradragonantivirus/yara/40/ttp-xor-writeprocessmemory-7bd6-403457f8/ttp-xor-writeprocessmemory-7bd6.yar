rule TTP_XOR_WriteProcessMemory_7bd6 {
  strings:
    $key_7bd6 = { 2c a4 [2] 1e 86 [2] 18 b3 [2] 36 b3 [2] 09 af }

  condition:
    any of them
}