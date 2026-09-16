rule TTP_XOR_WriteProcessMemory_25b1 {
  strings:
    $key_25b1 = { 72 c3 [2] 40 e1 [2] 46 d4 [2] 68 d4 [2] 57 c8 }

  condition:
    any of them
}