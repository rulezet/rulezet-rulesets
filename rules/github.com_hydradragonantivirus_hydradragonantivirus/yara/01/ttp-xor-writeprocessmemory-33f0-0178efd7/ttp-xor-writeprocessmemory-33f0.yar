rule TTP_XOR_WriteProcessMemory_33f0 {
  strings:
    $key_33f0 = { 64 82 [2] 56 a0 [2] 50 95 [2] 7e 95 [2] 41 89 }

  condition:
    any of them
}