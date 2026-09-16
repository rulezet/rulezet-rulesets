rule TTP_XOR_WriteProcessMemory_75a0 {
  strings:
    $key_75a0 = { 22 d2 [2] 10 f0 [2] 16 c5 [2] 38 c5 [2] 07 d9 }

  condition:
    any of them
}