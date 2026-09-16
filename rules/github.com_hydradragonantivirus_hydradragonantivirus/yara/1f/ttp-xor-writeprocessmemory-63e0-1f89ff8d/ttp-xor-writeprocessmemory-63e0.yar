rule TTP_XOR_WriteProcessMemory_63e0 {
  strings:
    $key_63e0 = { 34 92 [2] 06 b0 [2] 00 85 [2] 2e 85 [2] 11 99 }

  condition:
    any of them
}