rule TTP_XOR_WriteProcessMemory_73f0 {
  strings:
    $key_73f0 = { 24 82 [2] 16 a0 [2] 10 95 [2] 3e 95 [2] 01 89 }

  condition:
    any of them
}