rule TTP_XOR_WriteProcessMemory_77a0 {
  strings:
    $key_77a0 = { 20 d2 [2] 12 f0 [2] 14 c5 [2] 3a c5 [2] 05 d9 }

  condition:
    any of them
}