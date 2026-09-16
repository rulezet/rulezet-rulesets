rule TTP_XOR_WriteProcessMemory_30e2 {
  strings:
    $key_30e2 = { 67 90 [2] 55 b2 [2] 53 87 [2] 7d 87 [2] 42 9b }

  condition:
    any of them
}