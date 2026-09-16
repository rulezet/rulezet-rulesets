rule TTP_XOR_WriteProcessMemory_35f0 {
  strings:
    $key_35f0 = { 62 82 [2] 50 a0 [2] 56 95 [2] 78 95 [2] 47 89 }

  condition:
    any of them
}