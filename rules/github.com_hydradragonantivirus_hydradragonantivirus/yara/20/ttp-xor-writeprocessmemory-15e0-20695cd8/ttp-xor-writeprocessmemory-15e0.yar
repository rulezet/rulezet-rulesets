rule TTP_XOR_WriteProcessMemory_15e0 {
  strings:
    $key_15e0 = { 42 92 [2] 70 b0 [2] 76 85 [2] 58 85 [2] 67 99 }

  condition:
    any of them
}