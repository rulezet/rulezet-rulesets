rule TTP_XOR_WriteProcessMemory_33a0 {
  strings:
    $key_33a0 = { 64 d2 [2] 56 f0 [2] 50 c5 [2] 7e c5 [2] 41 d9 }

  condition:
    any of them
}