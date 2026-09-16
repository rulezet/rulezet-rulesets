rule TTP_XOR_WriteProcessMemory_07d9 {
  strings:
    $key_07d9 = { 50 ab [2] 62 89 [2] 64 bc [2] 4a bc [2] 75 a0 }

  condition:
    any of them
}