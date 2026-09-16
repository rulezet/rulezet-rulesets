rule TTP_XOR_WriteProcessMemory_5342 {
  strings:
    $key_5342 = { 04 30 [2] 36 12 [2] 30 27 [2] 1e 27 [2] 21 3b }

  condition:
    any of them
}