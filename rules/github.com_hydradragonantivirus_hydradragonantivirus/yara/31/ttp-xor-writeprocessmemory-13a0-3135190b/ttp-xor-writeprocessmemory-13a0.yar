rule TTP_XOR_WriteProcessMemory_13a0 {
  strings:
    $key_13a0 = { 44 d2 [2] 76 f0 [2] 70 c5 [2] 5e c5 [2] 61 d9 }

  condition:
    any of them
}