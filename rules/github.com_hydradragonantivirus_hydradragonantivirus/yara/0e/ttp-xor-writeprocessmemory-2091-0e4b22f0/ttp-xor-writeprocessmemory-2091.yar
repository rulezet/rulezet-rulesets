rule TTP_XOR_WriteProcessMemory_2091 {
  strings:
    $key_2091 = { 77 e3 [2] 45 c1 [2] 43 f4 [2] 6d f4 [2] 52 e8 }

  condition:
    any of them
}