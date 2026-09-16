rule TTP_XOR_WriteProcessMemory_1da0 {
  strings:
    $key_1da0 = { 4a d2 [2] 78 f0 [2] 7e c5 [2] 50 c5 [2] 6f d9 }

  condition:
    any of them
}