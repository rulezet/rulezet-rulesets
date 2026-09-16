rule TTP_XOR_WriteProcessMemory_4ed9 {
  strings:
    $key_4ed9 = { 19 ab [2] 2b 89 [2] 2d bc [2] 03 bc [2] 3c a0 }

  condition:
    any of them
}