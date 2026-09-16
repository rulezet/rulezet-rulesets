rule TTP_XOR_WriteProcessMemory_01d9 {
  strings:
    $key_01d9 = { 56 ab [2] 64 89 [2] 62 bc [2] 4c bc [2] 73 a0 }

  condition:
    any of them
}