rule TTP_XOR_WriteProcessMemory_07e0 {
  strings:
    $key_07e0 = { 50 92 [2] 62 b0 [2] 64 85 [2] 4a 85 [2] 75 99 }

  condition:
    any of them
}