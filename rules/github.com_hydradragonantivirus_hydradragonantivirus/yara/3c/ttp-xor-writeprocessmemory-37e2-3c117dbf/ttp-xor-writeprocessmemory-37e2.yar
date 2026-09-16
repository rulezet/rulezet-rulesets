rule TTP_XOR_WriteProcessMemory_37e2 {
  strings:
    $key_37e2 = { 60 90 [2] 52 b2 [2] 54 87 [2] 7a 87 [2] 45 9b }

  condition:
    any of them
}