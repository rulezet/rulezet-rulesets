rule TTP_XOR_WriteProcessMemory_59f0 {
  strings:
    $key_59f0 = { 0e 82 [2] 3c a0 [2] 3a 95 [2] 14 95 [2] 2b 89 }

  condition:
    any of them
}