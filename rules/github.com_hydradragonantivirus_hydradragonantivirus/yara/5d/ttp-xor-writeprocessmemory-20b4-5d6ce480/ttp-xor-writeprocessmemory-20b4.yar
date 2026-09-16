rule TTP_XOR_WriteProcessMemory_20b4 {
  strings:
    $key_20b4 = { 77 c6 [2] 45 e4 [2] 43 d1 [2] 6d d1 [2] 52 cd }

  condition:
    any of them
}