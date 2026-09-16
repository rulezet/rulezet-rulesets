rule TTP_XOR_WriteProcessMemory_2390 {
  strings:
    $key_2390 = { 74 e2 [2] 46 c0 [2] 40 f5 [2] 6e f5 [2] 51 e9 }

  condition:
    any of them
}