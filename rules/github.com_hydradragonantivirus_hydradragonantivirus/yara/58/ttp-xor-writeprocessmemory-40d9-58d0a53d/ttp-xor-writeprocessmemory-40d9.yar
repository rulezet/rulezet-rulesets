rule TTP_XOR_WriteProcessMemory_40d9 {
  strings:
    $key_40d9 = { 17 ab [2] 25 89 [2] 23 bc [2] 0d bc [2] 32 a0 }

  condition:
    any of them
}