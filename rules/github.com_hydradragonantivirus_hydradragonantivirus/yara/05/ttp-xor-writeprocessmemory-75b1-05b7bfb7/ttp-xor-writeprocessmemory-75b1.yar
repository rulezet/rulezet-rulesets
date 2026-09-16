rule TTP_XOR_WriteProcessMemory_75b1 {
  strings:
    $key_75b1 = { 22 c3 [2] 10 e1 [2] 16 d4 [2] 38 d4 [2] 07 c8 }

  condition:
    any of them
}