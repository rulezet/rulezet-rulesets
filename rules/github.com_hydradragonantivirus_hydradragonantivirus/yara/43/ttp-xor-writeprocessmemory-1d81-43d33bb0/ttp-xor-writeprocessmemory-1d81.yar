rule TTP_XOR_WriteProcessMemory_1d81 {
  strings:
    $key_1d81 = { 4a f3 [2] 78 d1 [2] 7e e4 [2] 50 e4 [2] 6f f8 }

  condition:
    any of them
}