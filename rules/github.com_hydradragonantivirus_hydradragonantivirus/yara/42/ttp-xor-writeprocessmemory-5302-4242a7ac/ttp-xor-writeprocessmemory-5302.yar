rule TTP_XOR_WriteProcessMemory_5302 {
  strings:
    $key_5302 = { 04 70 [2] 36 52 [2] 30 67 [2] 1e 67 [2] 21 7b }

  condition:
    any of them
}