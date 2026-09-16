rule TTP_XOR_WriteProcessMemory_17e2 {
  strings:
    $key_17e2 = { 40 90 [2] 72 b2 [2] 74 87 [2] 5a 87 [2] 65 9b }

  condition:
    any of them
}