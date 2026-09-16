rule TTP_XOR_WriteProcessMemory_53d9 {
  strings:
    $key_53d9 = { 04 ab [2] 36 89 [2] 30 bc [2] 1e bc [2] 21 a0 }

  condition:
    any of them
}