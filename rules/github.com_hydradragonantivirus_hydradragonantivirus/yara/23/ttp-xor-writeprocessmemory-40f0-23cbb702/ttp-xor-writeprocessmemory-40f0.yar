rule TTP_XOR_WriteProcessMemory_40f0 {
  strings:
    $key_40f0 = { 17 82 [2] 25 a0 [2] 23 95 [2] 0d 95 [2] 32 89 }

  condition:
    any of them
}