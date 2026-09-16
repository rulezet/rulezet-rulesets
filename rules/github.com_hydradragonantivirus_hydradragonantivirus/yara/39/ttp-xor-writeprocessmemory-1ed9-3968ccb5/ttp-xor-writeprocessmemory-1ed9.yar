rule TTP_XOR_WriteProcessMemory_1ed9 {
  strings:
    $key_1ed9 = { 49 ab [2] 7b 89 [2] 7d bc [2] 53 bc [2] 6c a0 }

  condition:
    any of them
}