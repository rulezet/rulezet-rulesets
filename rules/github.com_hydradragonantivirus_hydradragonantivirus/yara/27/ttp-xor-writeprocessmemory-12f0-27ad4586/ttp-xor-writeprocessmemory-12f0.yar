rule TTP_XOR_WriteProcessMemory_12f0 {
  strings:
    $key_12f0 = { 45 82 [2] 77 a0 [2] 71 95 [2] 5f 95 [2] 60 89 }

  condition:
    any of them
}