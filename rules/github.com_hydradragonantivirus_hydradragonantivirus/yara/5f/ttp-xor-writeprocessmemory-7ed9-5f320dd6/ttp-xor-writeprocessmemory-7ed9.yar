rule TTP_XOR_WriteProcessMemory_7ed9 {
  strings:
    $key_7ed9 = { 29 ab [2] 1b 89 [2] 1d bc [2] 33 bc [2] 0c a0 }

  condition:
    any of them
}