rule TTP_XOR_WriteProcessMemory_53f0 {
  strings:
    $key_53f0 = { 04 82 [2] 36 a0 [2] 30 95 [2] 1e 95 [2] 21 89 }

  condition:
    any of them
}