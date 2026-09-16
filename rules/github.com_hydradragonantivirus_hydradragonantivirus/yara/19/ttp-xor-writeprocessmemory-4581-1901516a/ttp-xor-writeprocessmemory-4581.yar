rule TTP_XOR_WriteProcessMemory_4581 {
  strings:
    $key_4581 = { 12 f3 [2] 20 d1 [2] 26 e4 [2] 08 e4 [2] 37 f8 }

  condition:
    any of them
}