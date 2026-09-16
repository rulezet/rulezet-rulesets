rule TTP_XOR_WriteProcessMemory_60d9 {
  strings:
    $key_60d9 = { 37 ab [2] 05 89 [2] 03 bc [2] 2d bc [2] 12 a0 }

  condition:
    any of them
}