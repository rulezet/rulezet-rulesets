rule TTP_XOR_WriteProcessMemory_57d9 {
  strings:
    $key_57d9 = { 00 ab [2] 32 89 [2] 34 bc [2] 1a bc [2] 25 a0 }

  condition:
    any of them
}