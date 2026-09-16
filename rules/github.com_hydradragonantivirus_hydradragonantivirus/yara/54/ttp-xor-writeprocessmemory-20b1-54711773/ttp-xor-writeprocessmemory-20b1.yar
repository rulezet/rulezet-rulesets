rule TTP_XOR_WriteProcessMemory_20b1 {
  strings:
    $key_20b1 = { 77 c3 [2] 45 e1 [2] 43 d4 [2] 6d d4 [2] 52 c8 }

  condition:
    any of them
}