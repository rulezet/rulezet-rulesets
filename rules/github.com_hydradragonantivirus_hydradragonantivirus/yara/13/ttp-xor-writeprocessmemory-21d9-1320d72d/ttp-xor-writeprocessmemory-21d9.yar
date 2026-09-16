rule TTP_XOR_WriteProcessMemory_21d9 {
  strings:
    $key_21d9 = { 76 ab [2] 44 89 [2] 42 bc [2] 6c bc [2] 53 a0 }

  condition:
    any of them
}