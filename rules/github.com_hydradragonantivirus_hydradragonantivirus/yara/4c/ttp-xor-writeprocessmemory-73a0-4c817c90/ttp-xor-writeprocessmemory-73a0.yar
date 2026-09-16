rule TTP_XOR_WriteProcessMemory_73a0 {
  strings:
    $key_73a0 = { 24 d2 [2] 16 f0 [2] 10 c5 [2] 3e c5 [2] 01 d9 }

  condition:
    any of them
}