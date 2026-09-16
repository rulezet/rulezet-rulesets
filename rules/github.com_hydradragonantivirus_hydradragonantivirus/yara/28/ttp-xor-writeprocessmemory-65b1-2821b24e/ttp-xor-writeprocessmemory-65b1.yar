rule TTP_XOR_WriteProcessMemory_65b1 {
  strings:
    $key_65b1 = { 32 c3 [2] 00 e1 [2] 06 d4 [2] 28 d4 [2] 17 c8 }

  condition:
    any of them
}