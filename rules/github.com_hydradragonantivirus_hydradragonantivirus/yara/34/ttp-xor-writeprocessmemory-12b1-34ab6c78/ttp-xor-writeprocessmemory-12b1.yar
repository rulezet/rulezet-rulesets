rule TTP_XOR_WriteProcessMemory_12b1 {
  strings:
    $key_12b1 = { 45 c3 [2] 77 e1 [2] 71 d4 [2] 5f d4 [2] 60 c8 }

  condition:
    any of them
}