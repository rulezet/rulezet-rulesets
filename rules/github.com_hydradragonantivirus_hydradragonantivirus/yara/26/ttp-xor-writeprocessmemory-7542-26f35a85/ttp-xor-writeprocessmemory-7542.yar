rule TTP_XOR_WriteProcessMemory_7542 {
  strings:
    $key_7542 = { 22 30 [2] 10 12 [2] 16 27 [2] 38 27 [2] 07 3b }

  condition:
    any of them
}