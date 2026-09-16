rule TTP_XOR_WriteProcessMemory_17e0 {
  strings:
    $key_17e0 = { 40 92 [2] 72 b0 [2] 74 85 [2] 5a 85 [2] 65 99 }

  condition:
    any of them
}