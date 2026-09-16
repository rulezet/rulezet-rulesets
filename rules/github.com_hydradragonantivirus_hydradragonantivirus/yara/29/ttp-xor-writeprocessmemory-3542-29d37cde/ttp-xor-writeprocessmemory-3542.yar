rule TTP_XOR_WriteProcessMemory_3542 {
  strings:
    $key_3542 = { 62 30 [2] 50 12 [2] 56 27 [2] 78 27 [2] 47 3b }

  condition:
    any of them
}