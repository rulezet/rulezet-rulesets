rule TTP_XOR_WriteProcessMemory_47e2 {
  strings:
    $key_47e2 = { 10 90 [2] 22 b2 [2] 24 87 [2] 0a 87 [2] 35 9b }

  condition:
    any of them
}