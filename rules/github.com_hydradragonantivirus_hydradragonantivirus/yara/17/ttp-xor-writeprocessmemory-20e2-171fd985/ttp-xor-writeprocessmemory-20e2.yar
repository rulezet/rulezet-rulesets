rule TTP_XOR_WriteProcessMemory_20e2 {
  strings:
    $key_20e2 = { 77 90 [2] 45 b2 [2] 43 87 [2] 6d 87 [2] 52 9b }

  condition:
    any of them
}