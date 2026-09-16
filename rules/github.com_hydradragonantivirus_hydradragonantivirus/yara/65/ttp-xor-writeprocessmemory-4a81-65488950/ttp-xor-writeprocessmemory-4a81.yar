rule TTP_XOR_WriteProcessMemory_4a81 {
  strings:
    $key_4a81 = { 1d f3 [2] 2f d1 [2] 29 e4 [2] 07 e4 [2] 38 f8 }

  condition:
    any of them
}