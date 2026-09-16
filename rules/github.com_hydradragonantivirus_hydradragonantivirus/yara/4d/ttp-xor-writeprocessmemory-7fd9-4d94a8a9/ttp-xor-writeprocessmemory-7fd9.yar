rule TTP_XOR_WriteProcessMemory_7fd9 {
  strings:
    $key_7fd9 = { 28 ab [2] 1a 89 [2] 1c bc [2] 32 bc [2] 0d a0 }

  condition:
    any of them
}