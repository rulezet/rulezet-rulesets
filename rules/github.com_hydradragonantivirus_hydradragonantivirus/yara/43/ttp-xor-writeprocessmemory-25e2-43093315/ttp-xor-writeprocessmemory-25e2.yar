rule TTP_XOR_WriteProcessMemory_25e2 {
  strings:
    $key_25e2 = { 72 90 [2] 40 b2 [2] 46 87 [2] 68 87 [2] 57 9b }

  condition:
    any of them
}