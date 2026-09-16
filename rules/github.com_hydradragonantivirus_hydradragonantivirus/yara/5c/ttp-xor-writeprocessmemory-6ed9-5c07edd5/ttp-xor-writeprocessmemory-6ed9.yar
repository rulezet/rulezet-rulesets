rule TTP_XOR_WriteProcessMemory_6ed9 {
  strings:
    $key_6ed9 = { 39 ab [2] 0b 89 [2] 0d bc [2] 23 bc [2] 1c a0 }

  condition:
    any of them
}