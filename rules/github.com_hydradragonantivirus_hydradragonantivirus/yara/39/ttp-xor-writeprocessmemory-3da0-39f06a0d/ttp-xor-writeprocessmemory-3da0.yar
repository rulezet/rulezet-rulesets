rule TTP_XOR_WriteProcessMemory_3da0 {
  strings:
    $key_3da0 = { 6a d2 [2] 58 f0 [2] 5e c5 [2] 70 c5 [2] 4f d9 }

  condition:
    any of them
}