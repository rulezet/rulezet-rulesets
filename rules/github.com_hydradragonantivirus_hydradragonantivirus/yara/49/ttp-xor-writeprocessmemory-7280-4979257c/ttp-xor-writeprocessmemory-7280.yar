rule TTP_XOR_WriteProcessMemory_7280 {
  strings:
    $key_7280 = { 25 f2 [2] 17 d0 [2] 11 e5 [2] 3f e5 [2] 00 f9 }

  condition:
    any of them
}