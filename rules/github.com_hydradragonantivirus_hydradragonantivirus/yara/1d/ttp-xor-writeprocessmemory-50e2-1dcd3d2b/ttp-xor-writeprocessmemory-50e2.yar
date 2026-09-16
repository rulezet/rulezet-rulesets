rule TTP_XOR_WriteProcessMemory_50e2 {
  strings:
    $key_50e2 = { 07 90 [2] 35 b2 [2] 33 87 [2] 1d 87 [2] 22 9b }

  condition:
    any of them
}