rule TTP_XOR_WriteProcessMemory_5280 {
  strings:
    $key_5280 = { 05 f2 [2] 37 d0 [2] 31 e5 [2] 1f e5 [2] 20 f9 }

  condition:
    any of them
}