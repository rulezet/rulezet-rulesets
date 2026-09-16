rule TTP_XOR_WriteProcessMemory_4280 {
  strings:
    $key_4280 = { 15 f2 [2] 27 d0 [2] 21 e5 [2] 0f e5 [2] 30 f9 }

  condition:
    any of them
}