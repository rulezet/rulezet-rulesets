rule TTP_XOR_WriteProcessMemory_53c0 {
  strings:
    $key_53c0 = { 04 b2 [2] 36 90 [2] 30 a5 [2] 1e a5 [2] 21 b9 }

  condition:
    any of them
}