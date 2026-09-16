rule TTP_XOR_WriteProcessMemory_31d9 {
  strings:
    $key_31d9 = { 66 ab [2] 54 89 [2] 52 bc [2] 7c bc [2] 43 a0 }

  condition:
    any of them
}